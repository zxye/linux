#include <linux/perf_event.h>
#include <linux/sizes.h>

#include "i915_drv.h"
#include "intel_ringbuffer.h"

/* Must be a power of two */
#define OA_BUFFER_SIZE	     SZ_16M
#define OA_TAKEN(tail, head) ((tail - head) & (OA_BUFFER_SIZE - 1))

#define FREQUENCY 200
#define PERIOD max_t(u64, 10000, NSEC_PER_SEC / FREQUENCY)

#define TS_DATA_SIZE sizeof(struct drm_i915_ts_data)
#define CTX_INFO_SIZE sizeof(struct drm_i915_ts_node_ctx_id)

static u32 i915_oa_event_paranoid = true;

static int hsw_perf_format_sizes[] = {
	64,  /* A13_HSW */
	128, /* A29_HSW */
	128, /* A13_B8_C8_HSW */
	-1,  /* Disallowed since 192 bytes doesn't factor into buffer size
		(A29_B8_C8_HSW) */
	64,  /* B4_C8_HSW */
	256, /* A45_B8_C8_HSW */
	128, /* B4_C8_A16_HSW */
	64   /* C4_B8_HSW */
};

void i915_emit_profiling_data(struct drm_i915_gem_request *req,
				u32 global_ctx_id, u32 tag)
{
	struct intel_engine_cs *ring = req->ring;
	struct drm_i915_private *dev_priv = ring->dev->dev_private;
	int i;

	for (i = I915_PROFILE_OA; i < I915_PROFILE_MAX; i++) {
		if (dev_priv->emit_profiling_data[i])
			dev_priv->emit_profiling_data[i](req, global_ctx_id,
							tag);
	}
}

/*
 * Emits the commands to capture OA perf report, into the Render CS
 */
static void i915_oa_emit_perf_report(struct drm_i915_gem_request *req,
				u32 global_ctx_id, u32 tag)
{
	struct intel_engine_cs *ring = req->ring;
	struct drm_i915_private *dev_priv = ring->dev->dev_private;
	struct drm_i915_gem_object *obj = dev_priv->oa_pmu.oa_rcs_buffer.obj;
	struct i915_oa_rcs_node *entry;
	unsigned long lock_flags;
	u32 addr = 0;
	int ret;

	/* OA counters are only supported on the render ring */
	if (ring->id != RCS)
		return;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (entry == NULL) {
		DRM_ERROR("alloc failed\n");
		return;
	}

	ret = intel_ring_begin(ring, 4);
	if (ret) {
		kfree(entry);
		return;
	}

	entry->ctx_id = global_ctx_id;
	if (dev_priv->oa_pmu.sample_info_flags & I915_OA_SAMPLE_PID)
		entry->pid = current->pid;
	if (dev_priv->oa_pmu.sample_info_flags & I915_OA_SAMPLE_TAG)
		entry->tag = tag;
	i915_gem_request_assign(&entry->req, ring->outstanding_lazy_request);

	spin_lock_irqsave(&dev_priv->oa_pmu.lock, lock_flags);
	if (list_empty(&dev_priv->oa_pmu.node_list))
		entry->offset = 0;
	else {
		struct i915_oa_rcs_node *last_entry;
		int max_offset = dev_priv->oa_pmu.oa_rcs_buffer.node_count *
				dev_priv->oa_pmu.oa_rcs_buffer.node_size;

		last_entry = list_last_entry(&dev_priv->oa_pmu.node_list,
					struct i915_oa_rcs_node, head);
		entry->offset = last_entry->offset +
				dev_priv->oa_pmu.oa_rcs_buffer.node_size;

		if (entry->offset > max_offset)
			entry->offset = 0;
	}
	list_add_tail(&entry->head, &dev_priv->oa_pmu.node_list);
	spin_unlock_irqrestore(&dev_priv->oa_pmu.lock, lock_flags);

	addr = dev_priv->oa_pmu.oa_rcs_buffer.gtt_offset + entry->offset;

	/* addr should be 64 byte aligned */
	BUG_ON(addr & 0x3f);

	intel_ring_emit(ring, MI_REPORT_PERF_COUNT | (1<<0));
	intel_ring_emit(ring, addr | MI_REPORT_PERF_COUNT_GGTT);
	intel_ring_emit(ring, ring->outstanding_lazy_request->seqno);
	intel_ring_emit(ring, MI_NOOP);
	intel_ring_advance(ring);

	obj->base.write_domain = I915_GEM_DOMAIN_RENDER;
	i915_vma_move_to_active(dev_priv->oa_pmu.oa_rcs_buffer.vma, ring);
}

static void forward_one_oa_snapshot_to_event(struct drm_i915_private *dev_priv,
					     u8 *snapshot,
					     struct perf_event *event)
{
	struct perf_sample_data data;
	int snapshot_size = dev_priv->oa_pmu.oa_buffer.format_size;
	struct perf_raw_record raw;

	WARN_ON(snapshot_size == 0);

	perf_sample_data_init(&data, 0, event->hw.last_period);

	/* Note: the combined u32 raw->size member + raw data itself must be 8
	 * byte aligned. (See note in init_oa_buffer for more details) */
	raw.size = snapshot_size + 4;
	raw.data = snapshot;

	data.raw = &raw;

	perf_event_overflow(event, &data, &dev_priv->oa_pmu.dummy_regs);
}

static u32 forward_oa_snapshots(struct drm_i915_private *dev_priv,
				u32 head, u32 tail, u64 gpu_ts)
{
	struct perf_event *exclusive_event = dev_priv->oa_pmu.exclusive_event;
	int snapshot_size = dev_priv->oa_pmu.oa_buffer.format_size;
	u8 *oa_buf_base = dev_priv->oa_pmu.oa_buffer.addr;
	u32 mask = (OA_BUFFER_SIZE - 1);
	u8 *snapshot;
	u32 taken;

	head -= dev_priv->oa_pmu.oa_buffer.gtt_offset;
	tail -= dev_priv->oa_pmu.oa_buffer.gtt_offset;

	/* Note: the gpu doesn't wrap the tail according to the OA buffer size
	 * so when we need to make sure our head/tail values are in-bounds we
	 * use the above mask.
	 */

	while ((taken = OA_TAKEN(tail, head))) {
		u64 snapshot_ts;

		/* The tail increases in 64 byte increments, not in
		 * format_size steps. */
		if (taken < snapshot_size)
			break;

		snapshot = oa_buf_base + (head & mask);

		snapshot_ts = *(u64 *)(snapshot + 4);
		if (snapshot_ts > gpu_ts)
			break;

		head += snapshot_size;

		/* We currently only allow exclusive access to the counters
		 * so only have one event to forward too... */
		if (dev_priv->oa_pmu.event_state == I915_OA_EVENT_STARTED)
			forward_one_oa_snapshot_to_event(dev_priv, snapshot,
							 exclusive_event);
	}

	return dev_priv->oa_pmu.oa_buffer.gtt_offset + head;
}

static void log_oa_status(struct drm_i915_private *dev_priv,
			  enum drm_i915_oa_event_type status)
{
	struct {
		struct perf_event_header header;
		drm_i915_oa_event_header_t i915_oa_header;
	} oa_event;
	struct perf_output_handle handle;
	struct perf_sample_data sample_data;
	struct perf_event *event = dev_priv->oa_pmu.exclusive_event;
	int ret;

	oa_event.header.size = sizeof(oa_event);
	oa_event.header.type = PERF_RECORD_DEVICE;
	oa_event.i915_oa_header.type = status;
	oa_event.i915_oa_header.__reserved_1 = 0;

	perf_event_header__init_id(&oa_event.header, &sample_data, event);

	ret = perf_output_begin(&handle, event, oa_event.header.size);
	if (ret)
		return;

	perf_output_put(&handle, oa_event);
	perf_event__output_id_sample(event, &handle, &sample_data);
	perf_output_end(&handle);
}

static void flush_oa_snapshots(struct drm_i915_private *dev_priv,
			       bool skip_if_flushing, u64 gpu_ts)
{
	unsigned long flags;
	u32 oastatus2;
	u32 oastatus1;
	u32 head;
	u32 tail;

	/* Can either flush via hrtimer callback or pmu methods/fops */
	if (skip_if_flushing) {

		/* If the hrtimer triggers at the same time that we are
		 * responding to a userspace initiated flush then we can
		 * just bail out...
		 */
		if (!spin_trylock_irqsave(&dev_priv->oa_pmu.oa_buffer.flush_lock,
					  flags))
			return;
	} else
		spin_lock_irqsave(&dev_priv->oa_pmu.oa_buffer.flush_lock, flags);

	WARN_ON(!dev_priv->oa_pmu.oa_buffer.addr);

	oastatus2 = I915_READ(GEN7_OASTATUS2);
	oastatus1 = I915_READ(GEN7_OASTATUS1);

	head = oastatus2 & GEN7_OASTATUS2_HEAD_MASK;
	tail = oastatus1 & GEN7_OASTATUS1_TAIL_MASK;

	if (unlikely(oastatus1 & (GEN7_OASTATUS1_OABUFFER_OVERFLOW |
				  GEN7_OASTATUS1_REPORT_LOST))) {

		if (oastatus1 & GEN7_OASTATUS1_OABUFFER_OVERFLOW)
			log_oa_status(dev_priv, I915_OA_RECORD_BUFFER_OVERFLOW);

		if (oastatus1 & GEN7_OASTATUS1_REPORT_LOST)
			log_oa_status(dev_priv, I915_OA_RECORD_REPORT_LOST);

		I915_WRITE(GEN7_OASTATUS1, oastatus1 &
			   ~(GEN7_OASTATUS1_OABUFFER_OVERFLOW |
			     GEN7_OASTATUS1_REPORT_LOST));
	}

	head = forward_oa_snapshots(dev_priv, head, tail, gpu_ts);

	I915_WRITE(GEN7_OASTATUS2, (head & GEN7_OASTATUS2_HEAD_MASK) |
				    GEN7_OASTATUS2_GGTT);

	spin_unlock_irqrestore(&dev_priv->oa_pmu.oa_buffer.flush_lock, flags);
}

static int i915_oa_rcs_wait_gpu(struct drm_i915_private *dev_priv)
{
	struct i915_oa_rcs_node *last_entry = NULL;
	int ret = 0;

	/*
	 * Wait for the last scheduled request to complete. This would
	 * implicitly wait for the prior submitted requests. The refcount
	 * of the requests is not decremented here.
	 */
	spin_lock(&dev_priv->oa_pmu.lock);

	if (!list_empty(&dev_priv->oa_pmu.node_list)) {
		last_entry = list_last_entry(&dev_priv->oa_pmu.node_list,
			struct i915_oa_rcs_node, head);
	}
	spin_unlock(&dev_priv->oa_pmu.lock);

	if (!last_entry)
		return 0;

	ret = __i915_wait_request(last_entry->req, atomic_read(
			&dev_priv->gpu_error.reset_counter),
			true, NULL, NULL);
	if (ret) {
		DRM_ERROR("failed to wait\n");
		return ret;
	}
	return 0;
}

static void i915_oa_rcs_release_request_ref(struct drm_i915_private *dev_priv)
{
	struct i915_oa_rcs_node *entry, *next;

	list_for_each_entry_safe
		(entry, next, &dev_priv->oa_pmu.node_list, head) {
		i915_gem_request_unreference__unlocked(entry->req);

		spin_lock(&dev_priv->oa_pmu.lock);
		list_del(&entry->head);
		spin_unlock(&dev_priv->oa_pmu.lock);
		kfree(entry);
	}
}

static void forward_one_oa_rcs_sample(struct drm_i915_private *dev_priv,
				struct i915_oa_rcs_node *node)
{
	struct perf_sample_data data;
	struct perf_event *event = dev_priv->oa_pmu.exclusive_event;
	int format_size, snapshot_size;
	u8 *snapshot, *current_ptr;
	struct drm_i915_oa_node_ctx_id *ctx_info;
	struct drm_i915_oa_node_pid *pid_info;
	struct drm_i915_oa_node_tag *tag_info;
	struct perf_raw_record raw;
	u64 snapshot_ts;

	format_size = dev_priv->oa_pmu.oa_rcs_buffer.format_size;
	snapshot_size = format_size + sizeof(*ctx_info);
	snapshot = dev_priv->oa_pmu.oa_rcs_buffer.addr + node->offset;

	ctx_info = (struct drm_i915_oa_node_ctx_id *)(snapshot + format_size);
	ctx_info->ctx_id = node->ctx_id;
	current_ptr = snapshot + snapshot_size;

	if (dev_priv->oa_pmu.sample_info_flags & I915_OA_SAMPLE_PID) {
		pid_info = (struct drm_i915_oa_node_pid *)current_ptr;
		pid_info->pid = node->pid;
		snapshot_size += sizeof(*pid_info);
		current_ptr = snapshot + snapshot_size;
	}

	if (dev_priv->oa_pmu.sample_info_flags & I915_OA_SAMPLE_TAG) {
		tag_info = (struct drm_i915_oa_node_tag *)current_ptr;
		tag_info->tag = node->tag;
		snapshot_size += sizeof(*tag_info);
		current_ptr = snapshot + snapshot_size;
	}

	/* Flush the periodic snapshots till the ts of this OA report */
	snapshot_ts = *(u64 *)(snapshot + 4);
	flush_oa_snapshots(dev_priv, true, snapshot_ts);

	perf_sample_data_init(&data, 0, event->hw.last_period);

	/* Note: the raw sample consists of a u32 size member and raw data. The
	 * combined size of these two fields is required to be 8 byte aligned.
	 * The size of raw data field is assumed to be 8 byte aligned already.
	 * Therefore, adding 4 bytes to the total size here. We can't use
	 * BUILD_BUG_ON here as snapshot size is derived at runtime.
	 */
	raw.size = snapshot_size + 4;
	raw.data = snapshot;

	data.raw = &raw;

	perf_event_overflow(event, &data, &dev_priv->oa_pmu.dummy_regs);
}

/*
 * Routine to forward the samples to perf. This may be called from the event
 * flush and worker thread. This function may sleep, hence can't be called from
 * atomic contexts directly.
 */
static void forward_oa_rcs_snapshots(struct drm_i915_private *dev_priv)
{
	struct i915_oa_rcs_node *entry, *next;
	LIST_HEAD(deferred_list_free);
	int ret;

	list_for_each_entry_safe
		(entry, next, &dev_priv->oa_pmu.node_list, head) {
		if (!i915_gem_request_completed(entry->req, true))
			break;

		if (!entry->discard)
			forward_one_oa_rcs_sample(dev_priv, entry);

		spin_lock(&dev_priv->oa_pmu.lock);
		list_move_tail(&entry->head, &deferred_list_free);
		spin_unlock(&dev_priv->oa_pmu.lock);
	}

	ret = i915_mutex_lock_interruptible(dev_priv->dev);
	if (ret)
		return;
	while (!list_empty(&deferred_list_free)) {
		entry = list_first_entry(&deferred_list_free,
					struct i915_oa_rcs_node, head);
		i915_gem_request_unreference(entry->req);
		list_del(&entry->head);
		kfree(entry);
	}
	mutex_unlock(&dev_priv->dev->struct_mutex);
}

/*
 * Work fn to forward the snapshots. The forwarding of samples is trigged from
 * hrtimer and event_stop (both atomic contexts). The forward function may
 * sleep, hence the need for worker.
 */
static void forward_oa_rcs_work_fn(struct work_struct *__work)
{
	struct drm_i915_private *dev_priv =
		container_of(__work, typeof(*dev_priv), oa_pmu.forward_work);

	spin_lock(&dev_priv->oa_pmu.lock);
	if (dev_priv->oa_pmu.event_state != I915_OA_EVENT_STARTED) {
		spin_unlock(&dev_priv->oa_pmu.lock);
		return;
	}
	spin_unlock(&dev_priv->oa_pmu.lock);

	forward_oa_rcs_snapshots(dev_priv);
}

static int i915_gen_pmu_wait_gpu(struct drm_i915_private *dev_priv)
{
	struct i915_gen_pmu_node *last_entry = NULL;
	int ret;

	/*
	 * Wait for the last scheduled request to complete. This would
	 * implicitly wait for the prior submitted requests. The refcount
	 * of the requests is not decremented here.
	 */
	spin_lock(&dev_priv->gen_pmu.lock);

	if (!list_empty(&dev_priv->gen_pmu.node_list)) {
		last_entry = list_last_entry(&dev_priv->gen_pmu.node_list,
			struct i915_gen_pmu_node, head);
	}
	spin_unlock(&dev_priv->gen_pmu.lock);

	if (!last_entry)
		return 0;

	ret = __i915_wait_request(last_entry->req, atomic_read(
			&dev_priv->gpu_error.reset_counter),
			true, NULL, NULL);
	if (ret) {
		DRM_ERROR("failed to wait\n");
		return ret;
	}
	return 0;
}

static void i915_gen_pmu_release_request_ref(struct drm_i915_private *dev_priv)
{
	struct i915_gen_pmu_node *entry, *next;

	list_for_each_entry_safe
		(entry, next, &dev_priv->gen_pmu.node_list, head) {
		i915_gem_request_unreference__unlocked(entry->req);

		spin_lock(&dev_priv->gen_pmu.lock);
		list_del(&entry->head);
		spin_unlock(&dev_priv->gen_pmu.lock);
		kfree(entry);
	}
}

static void forward_one_gen_pmu_sample(struct drm_i915_private *dev_priv,
				struct i915_gen_pmu_node *node)
{
	struct perf_sample_data data;
	struct perf_event *event = dev_priv->gen_pmu.exclusive_event;
	int snapshot_size;
	u8 *snapshot;
	struct drm_i915_ts_node_ctx_id *ctx_info;
	struct perf_raw_record raw;

	BUILD_BUG_ON(TS_DATA_SIZE != 8);
	BUILD_BUG_ON(CTX_INFO_SIZE != 8);

	snapshot = dev_priv->gen_pmu.buffer.addr + node->offset;
	snapshot_size = TS_DATA_SIZE + CTX_INFO_SIZE;

	ctx_info = (struct drm_i915_ts_node_ctx_id *)(snapshot + TS_DATA_SIZE);
	ctx_info->ctx_id = node->ctx_id;

	/* Note: the raw sample consists of a u32 size member and raw data. The
	 * combined size of these two fields is required to be 8 byte aligned.
	 * The size of raw data field is assumed to be 8 byte aligned already.
	 * Therefore, adding 4 bytes to the raw sample size here.
	 */
	BUILD_BUG_ON(((snapshot_size + 4 + sizeof(raw.size)) % 8) != 0);

	perf_sample_data_init(&data, 0, event->hw.last_period);
	raw.size = snapshot_size + 4;
	raw.data = snapshot;

	data.raw = &raw;
	perf_event_overflow(event, &data, &dev_priv->gen_pmu.dummy_regs);
}

/*
 * Routine to forward the samples to perf. This may be called from the event
 * flush and worker thread. This function may sleep, hence can't be called from
 * atomic contexts directly.
 */
static void forward_gen_pmu_snapshots(struct drm_i915_private *dev_priv)
{
	struct i915_gen_pmu_node *entry, *next;
	LIST_HEAD(deferred_list_free);
	int ret;

	list_for_each_entry_safe
		(entry, next, &dev_priv->gen_pmu.node_list, head) {
		if (!i915_gem_request_completed(entry->req, true))
			break;

		if (!entry->discard)
			forward_one_gen_pmu_sample(dev_priv, entry);

		spin_lock(&dev_priv->gen_pmu.lock);
		list_move_tail(&entry->head, &deferred_list_free);
		spin_unlock(&dev_priv->gen_pmu.lock);
	}

	ret = i915_mutex_lock_interruptible(dev_priv->dev);
	if (ret)
		return;
	while (!list_empty(&deferred_list_free)) {
		entry = list_first_entry(&deferred_list_free,
					struct i915_gen_pmu_node, head);
		i915_gem_request_unreference(entry->req);
		list_del(&entry->head);
		kfree(entry);
	}
	mutex_unlock(&dev_priv->dev->struct_mutex);
}

static void forward_gen_pmu_work_fn(struct work_struct *__work)
{
	struct drm_i915_private *dev_priv =
		container_of(__work, typeof(*dev_priv), gen_pmu.forward_work);

	spin_lock(&dev_priv->gen_pmu.lock);
	if (dev_priv->gen_pmu.event_active != true) {
		spin_unlock(&dev_priv->gen_pmu.lock);
		return;
	}
	spin_unlock(&dev_priv->gen_pmu.lock);

	forward_gen_pmu_snapshots(dev_priv);
}

static void
oa_rcs_buffer_destroy(struct drm_i915_private *i915)
{
	mutex_lock(&i915->dev->struct_mutex);
	vunmap(i915->oa_pmu.oa_rcs_buffer.addr);
	i915_gem_object_ggtt_unpin(i915->oa_pmu.oa_rcs_buffer.obj);
	drm_gem_object_unreference(&i915->oa_pmu.oa_rcs_buffer.obj->base);
	mutex_unlock(&i915->dev->struct_mutex);

	spin_lock(&i915->oa_pmu.lock);
	i915->oa_pmu.oa_rcs_buffer.obj = NULL;
	i915->oa_pmu.oa_rcs_buffer.gtt_offset = 0;
	i915->oa_pmu.oa_rcs_buffer.vma = NULL;
	i915->oa_pmu.oa_rcs_buffer.addr = NULL;
	spin_unlock(&i915->oa_pmu.lock);
}

static void
oa_buffer_destroy(struct drm_i915_private *i915)
{
	mutex_lock(&i915->dev->struct_mutex);
	vunmap(i915->oa_pmu.oa_buffer.addr);
	i915_gem_object_ggtt_unpin(i915->oa_pmu.oa_buffer.obj);
	drm_gem_object_unreference(&i915->oa_pmu.oa_buffer.obj->base);
	mutex_unlock(&i915->dev->struct_mutex);

	spin_lock(&i915->oa_pmu.lock);
	i915->oa_pmu.oa_buffer.obj = NULL;
	i915->oa_pmu.oa_buffer.gtt_offset = 0;
	i915->oa_pmu.oa_buffer.addr = NULL;
	spin_unlock(&i915->oa_pmu.lock);

}

static void i915_oa_event_destroy(struct perf_event *event)
{
	struct drm_i915_private *dev_priv =
		container_of(event->pmu, typeof(*dev_priv), oa_pmu.pmu);

	WARN_ON(event->parent);

	if (dev_priv->oa_pmu.multiple_ctx_mode) {
		cancel_work_sync(&dev_priv->oa_pmu.forward_work);
		schedule_work(&dev_priv->oa_pmu.event_destroy_work);

		BUG_ON(dev_priv->oa_pmu.exclusive_event != event);
		dev_priv->oa_pmu.exclusive_event = NULL;

		/* We can deference our local copy of rcs buffer here, since
		 * an active reference of buffer would be taken while
		 * inserting commands. So the buffer would be freed up only
		 * after GPU is done with it.
		 */
		oa_rcs_buffer_destroy(dev_priv);
	} else {
		/* Stop updating oacontrol via _oa_context_[un]pin_notify() */
		spin_lock(&dev_priv->oa_pmu.lock);
		dev_priv->oa_pmu.specific_ctx = NULL;
		spin_unlock(&dev_priv->oa_pmu.lock);

		/* Don't let the compiler start resetting OA, PM and clock
		 * gating state before we've stopped update_oacontrol()
		 */
		barrier();

		BUG_ON(dev_priv->oa_pmu.exclusive_event != event);
		dev_priv->oa_pmu.exclusive_event = NULL;

		oa_buffer_destroy(dev_priv);

		I915_WRITE(GEN6_UCGCTL1, (I915_READ(GEN6_UCGCTL1) &
					  ~GEN6_CSUNIT_CLOCK_GATE_DISABLE));
		I915_WRITE(GEN7_MISCCPCTL, (I915_READ(GEN7_MISCCPCTL) |
					    GEN7_DOP_CLOCK_GATE_ENABLE));

		I915_WRITE(GDT_CHICKEN_BITS, (I915_READ(GDT_CHICKEN_BITS) &
					      ~GT_NOA_ENABLE));

		intel_uncore_forcewake_put(dev_priv, FORCEWAKE_ALL);
		intel_runtime_pm_put(dev_priv);
		dev_priv->oa_pmu.event_state = I915_OA_EVENT_INIT;
	}
}

static void i915_oa_rcs_event_destroy_work(struct work_struct *__work)
{
	struct drm_i915_private *dev_priv =
		container_of(__work, typeof(*dev_priv),
			oa_pmu.event_destroy_work);
	int ret;

	ret = i915_oa_rcs_wait_gpu(dev_priv);
	if (ret)
		goto out;

	i915_oa_rcs_release_request_ref(dev_priv);

out:
	/* Stop updating oacontrol via _oa_context_[un]pin_notify() */
	spin_lock(&dev_priv->oa_pmu.lock);
	dev_priv->oa_pmu.specific_ctx = NULL;
	spin_unlock(&dev_priv->oa_pmu.lock);

	/* Disable OA unit */
	I915_WRITE(GEN7_OACONTROL, 0);

	/* The periodic OA buffer has to be destroyed here, since
	 * this can be done only after OA unit is disabled. There is no active
	 * reference tracking mechanism for periodic OA buffer. So we can only
	 * dereference it in the worker after we've disabled OA unit (which we
	 * can do after we're sure to have completed the in flight GPU cmds)
	 */
	 /* TODO: Once we have callbacks in place on completion of request
	 * (i.e. when retire-notification patches land), we can take the active
	 * reference on LRI request(submitted for disabling OA) during event
	 * stop/destroy, and perform these actions, in the callback instead of
	 * work fn
	 */

	oa_buffer_destroy(dev_priv);

	spin_lock(&dev_priv->oa_pmu.lock);

	I915_WRITE(GEN6_UCGCTL1, (I915_READ(GEN6_UCGCTL1) &
				  ~GEN6_CSUNIT_CLOCK_GATE_DISABLE));
	I915_WRITE(GEN7_MISCCPCTL, (I915_READ(GEN7_MISCCPCTL) |
				    GEN7_DOP_CLOCK_GATE_ENABLE));

	I915_WRITE(GDT_CHICKEN_BITS, (I915_READ(GDT_CHICKEN_BITS) &
				      ~GT_NOA_ENABLE));

	intel_uncore_forcewake_put(dev_priv, FORCEWAKE_ALL);
	intel_runtime_pm_put(dev_priv);
	dev_priv->oa_pmu.event_state = I915_OA_EVENT_INIT;
	spin_unlock(&dev_priv->oa_pmu.lock);
}

static void gen_buffer_destroy(struct drm_i915_private *i915)
{
	mutex_lock(&i915->dev->struct_mutex);
	vunmap(i915->gen_pmu.buffer.addr);
	i915_gem_object_ggtt_unpin(i915->gen_pmu.buffer.obj);
	drm_gem_object_unreference(&i915->gen_pmu.buffer.obj->base);
	mutex_unlock(&i915->dev->struct_mutex);
}

static void i915_gen_event_destroy(struct perf_event *event)
{
	struct drm_i915_private *i915 =
		container_of(event->pmu, typeof(*i915), gen_pmu.pmu);

	WARN_ON(event->parent);

	cancel_work_sync(&i915->gen_pmu.forward_work);

	BUG_ON(i915->gen_pmu.exclusive_event != event);
	i915->gen_pmu.exclusive_event = NULL;

	/* We can deference our local copy of dest buffer here, since
	 * an active reference of buffer would be taken while
	 * inserting commands. So the buffer would be freed up only
	 * after GPU is done with it.
	 */
	gen_buffer_destroy(i915);

	schedule_work(&i915->gen_pmu.event_destroy_work);
}

static void i915_gen_pmu_event_destroy_work(struct work_struct *__work)
{
	struct drm_i915_private *dev_priv =
		container_of(__work, typeof(*dev_priv),
			gen_pmu.event_destroy_work);
	int ret;

	ret = i915_gen_pmu_wait_gpu(dev_priv);
	if (ret)
		goto out;

	i915_gen_pmu_release_request_ref(dev_priv);

out:
	/*
	 * Done here, as this excludes a new event till we've done processing
	 * the old one
	 */
	spin_lock(&dev_priv->gen_pmu.lock);
	dev_priv->gen_pmu.buffer.obj = NULL;
	dev_priv->gen_pmu.buffer.gtt_offset = 0;
	dev_priv->gen_pmu.buffer.addr = NULL;
	spin_unlock(&dev_priv->gen_pmu.lock);
}

static int alloc_obj(struct drm_i915_private *dev_priv,
				struct drm_i915_gem_object **obj)
{
	struct drm_i915_gem_object *bo;
	int ret;

	/* NB: We over allocate the OA buffer due to the way raw sample data
	 * gets copied from the gpu mapped circular buffer into the perf
	 * circular buffer so that only one copy is required.
	 *
	 * For each perf sample (raw->size + 4) needs to be 8 byte aligned,
	 * where the 4 corresponds to the 32bit raw->size member that's
	 * added to the sample header that userspace sees.
	 *
	 * Due to the + 4 for the size member: when we copy a report to the
	 * userspace facing perf buffer we always copy an additional 4 bytes
	 * from the subsequent report to make up for the miss alignment, but
	 * when a report is at the end of the gpu mapped buffer we need to
	 * read 4 bytes past the end of the buffer.
	 */
	intel_runtime_pm_get(dev_priv);

	ret = i915_mutex_lock_interruptible(dev_priv->dev);
	if (ret)
		goto out;

	bo = i915_gem_alloc_object(dev_priv->dev, OA_BUFFER_SIZE + PAGE_SIZE);
	if (bo == NULL) {
		DRM_ERROR("Failed to allocate OA buffer\n");
		ret = -ENOMEM;
		goto unlock;
	}
	ret = i915_gem_object_set_cache_level(bo, I915_CACHE_LLC);
	if (ret)
		goto err_unref;

	/* PreHSW required 512K alignment, HSW requires 16M */
	ret = i915_gem_obj_ggtt_pin(bo, SZ_16M, 0);
	if (ret)
		goto err_unref;

	*obj = bo;
	goto unlock;

err_unref:
	drm_gem_object_unreference(&bo->base);
unlock:
	mutex_unlock(&dev_priv->dev->struct_mutex);
out:
	intel_runtime_pm_put(dev_priv);
	return ret;
}

static void *vmap_oa_buffer(struct drm_i915_gem_object *obj)
{
	int i;
	void *addr = NULL;
	struct sg_page_iter sg_iter;
	struct page **pages;

	pages = drm_malloc_ab(obj->base.size >> PAGE_SHIFT, sizeof(*pages));
	if (pages == NULL) {
		DRM_DEBUG_DRIVER("Failed to get space for pages\n");
		goto finish;
	}

	i = 0;
	for_each_sg_page(obj->pages->sgl, &sg_iter, obj->pages->nents, 0) {
		pages[i] = sg_page_iter_page(&sg_iter);
		i++;
	}

	addr = vmap(pages, i, 0, PAGE_KERNEL);
	if (addr == NULL) {
		DRM_DEBUG_DRIVER("Failed to vmap pages\n");
		goto finish;
	}

finish:
	if (pages)
		drm_free_large(pages);
	return addr;
}

static int init_oa_buffer(struct perf_event *event)
{
	struct drm_i915_private *dev_priv =
		container_of(event->pmu, typeof(*dev_priv), oa_pmu.pmu);
	struct drm_i915_gem_object *bo;
	int ret;

	BUG_ON(!IS_HASWELL(dev_priv->dev));
	BUG_ON(dev_priv->oa_pmu.oa_buffer.obj);

	spin_lock_init(&dev_priv->oa_pmu.oa_buffer.flush_lock);

	ret = alloc_obj(dev_priv, &bo);
	if (ret)
		return ret;

	dev_priv->oa_pmu.oa_buffer.obj = bo;

	dev_priv->oa_pmu.oa_buffer.gtt_offset = i915_gem_obj_ggtt_offset(bo);
	dev_priv->oa_pmu.oa_buffer.addr = vmap_oa_buffer(bo);

	/* Pre-DevBDW: OABUFFER must be set with counters off,
	 * before OASTATUS1, but after OASTATUS2 */
	I915_WRITE(GEN7_OASTATUS2, dev_priv->oa_pmu.oa_buffer.gtt_offset |
		   GEN7_OASTATUS2_GGTT); /* head */
	I915_WRITE(GEN7_OABUFFER, dev_priv->oa_pmu.oa_buffer.gtt_offset);
	I915_WRITE(GEN7_OASTATUS1, dev_priv->oa_pmu.oa_buffer.gtt_offset |
		   GEN7_OASTATUS1_OABUFFER_SIZE_16M); /* tail */

	DRM_DEBUG_DRIVER("OA Buffer initialized, gtt offset = 0x%x, vaddr = %p",
			 dev_priv->oa_pmu.oa_buffer.gtt_offset,
			 dev_priv->oa_pmu.oa_buffer.addr);

	return 0;
}

static int init_oa_rcs_buffer(struct perf_event *event)
{
	struct drm_i915_private *dev_priv =
		container_of(event->pmu, typeof(*dev_priv), oa_pmu.pmu);
	struct drm_i915_gem_object *bo;
	int ret, node_size;

	BUG_ON(dev_priv->oa_pmu.oa_rcs_buffer.obj);

	ret = alloc_obj(dev_priv, &bo);
	if (ret)
		return ret;

	dev_priv->oa_pmu.oa_rcs_buffer.obj = bo;
	dev_priv->oa_pmu.oa_rcs_buffer.gtt_offset =
				i915_gem_obj_ggtt_offset(bo);
	dev_priv->oa_pmu.oa_rcs_buffer.vma = i915_gem_obj_to_ggtt(bo);
	dev_priv->oa_pmu.oa_rcs_buffer.addr = vmap_oa_buffer(bo);
	INIT_LIST_HEAD(&dev_priv->oa_pmu.node_list);

	node_size = dev_priv->oa_pmu.oa_rcs_buffer.format_size +
			sizeof(struct drm_i915_oa_node_ctx_id);

	if (dev_priv->oa_pmu.sample_info_flags & I915_OA_SAMPLE_PID)
		node_size += sizeof(struct drm_i915_oa_node_pid);

	if (dev_priv->oa_pmu.sample_info_flags & I915_OA_SAMPLE_TAG)
		node_size += sizeof(struct drm_i915_oa_node_tag);

	/* node size has to be aligned to 64 bytes, since only 64 byte aligned
	 * addresses can be given to OA unit for dumping OA reports */
	node_size = ALIGN(node_size, 64);
	dev_priv->oa_pmu.oa_rcs_buffer.node_size = node_size;
	dev_priv->oa_pmu.oa_rcs_buffer.node_count = bo->base.size / node_size;

	DRM_DEBUG_DRIVER("OA RCS Buffer initialized, vaddr = %p",
			 dev_priv->oa_pmu.oa_rcs_buffer.addr);

	return 0;
}

static int init_gen_pmu_buffer(struct perf_event *event)
{
	struct drm_i915_private *dev_priv =
		container_of(event->pmu, typeof(*dev_priv), gen_pmu.pmu);
	struct drm_i915_gem_object *bo;
	int ret, node_size;

	BUG_ON(dev_priv->gen_pmu.buffer.obj);

	ret = alloc_obj(dev_priv, &bo);
	if (ret)
		return ret;

	dev_priv->gen_pmu.buffer.obj = bo;
	dev_priv->gen_pmu.buffer.gtt_offset =
				i915_gem_obj_ggtt_offset(bo);
	dev_priv->gen_pmu.buffer.addr = vmap_oa_buffer(bo);
	INIT_LIST_HEAD(&dev_priv->gen_pmu.node_list);

	node_size = TS_DATA_SIZE + CTX_INFO_SIZE;

	/* size has to be aligned to 8 bytes */
	node_size = ALIGN(node_size, 8);
	dev_priv->gen_pmu.buffer.node_size = node_size;
	dev_priv->gen_pmu.buffer.node_count = bo->base.size / node_size;

	DRM_DEBUG_DRIVER("Gen PMU Buffer initialized, vaddr = %p",
			 dev_priv->gen_pmu.buffer.addr);

	return 0;
}

static enum hrtimer_restart hrtimer_sample_gen(struct hrtimer *hrtimer)
{
	struct drm_i915_private *i915 =
		container_of(hrtimer, typeof(*i915), gen_pmu.timer);

	schedule_work(&i915->gen_pmu.forward_work);

	hrtimer_forward_now(hrtimer, ns_to_ktime(PERIOD));
	return HRTIMER_RESTART;
}

static enum hrtimer_restart hrtimer_sample(struct hrtimer *hrtimer)
{
	struct drm_i915_private *i915 =
		container_of(hrtimer, typeof(*i915), oa_pmu.timer);

	if (i915->oa_pmu.multiple_ctx_mode)
		schedule_work(&i915->oa_pmu.forward_work);
	else
		flush_oa_snapshots(i915, true, U64_MAX);

	hrtimer_forward_now(hrtimer, ns_to_ktime(PERIOD));
	return HRTIMER_RESTART;
}

static struct intel_context *
lookup_context(struct drm_i915_private *dev_priv,
	       struct file *user_filp,
	       u32 ctx_user_handle)
{
	struct intel_context *ctx;

	mutex_lock(&dev_priv->dev->struct_mutex);
	list_for_each_entry(ctx, &dev_priv->context_list, link) {
		struct drm_file *drm_file;

		if (!ctx->file_priv)
			continue;

		drm_file = ctx->file_priv->file;

		if (user_filp->private_data == drm_file &&
		    ctx->user_handle == ctx_user_handle) {
			mutex_unlock(&dev_priv->dev->struct_mutex);
			return ctx;
		}
	}
	mutex_unlock(&dev_priv->dev->struct_mutex);

	return NULL;
}

static int i915_oa_copy_attr(drm_i915_oa_attr_t __user *uattr,
			     drm_i915_oa_attr_t *attr)
{
	u32 size;
	int ret;

	if (!access_ok(VERIFY_WRITE, uattr, I915_OA_ATTR_SIZE_VER0))
		return -EFAULT;

	/*
	 * zero the full structure, so that a short copy will be nice.
	 */
	memset(attr, 0, sizeof(*attr));

	ret = get_user(size, &uattr->size);
	if (ret)
		return ret;

	if (size > PAGE_SIZE)	/* silly large */
		goto err_size;

	if (size < I915_OA_ATTR_SIZE_VER0)
		goto err_size;

	/*
	 * If we're handed a bigger struct than we know of,
	 * ensure all the unknown bits are 0 - i.e. new
	 * user-space does not rely on any kernel feature
	 * extensions we dont know about yet.
	 */
	if (size > sizeof(*attr)) {
		unsigned char __user *addr;
		unsigned char __user *end;
		unsigned char val;

		addr = (void __user *)uattr + sizeof(*attr);
		end  = (void __user *)uattr + size;

		for (; addr < end; addr++) {
			ret = get_user(val, addr);
			if (ret)
				return ret;
			if (val)
				goto err_size;
		}
		size = sizeof(*attr);
	}

	ret = copy_from_user(attr, uattr, size);
	if (ret)
		return -EFAULT;

	if (attr->__reserved_1)
		return -EINVAL;

out:
	return ret;

err_size:
	put_user(sizeof(*attr), &uattr->size);
	ret = -E2BIG;
	goto out;
}

static int i915_oa_event_init(struct perf_event *event)
{
	struct drm_i915_private *dev_priv =
		container_of(event->pmu, typeof(*dev_priv), oa_pmu.pmu);
	drm_i915_oa_attr_t oa_attr;
	u64 report_format;
	int ret = 0;

	if (event->attr.type != event->pmu->type)
		return -ENOENT;

	ret = i915_oa_copy_attr(to_user_ptr(event->attr.config), &oa_attr);
	if (ret)
		return ret;

	/* To avoid the complexity of having to accurately filter
	 * counter snapshots and marshal to the appropriate client
	 * we currently only allow exclusive access */
	spin_lock(&dev_priv->oa_pmu.lock);
	if (dev_priv->oa_pmu.oa_buffer.obj ||
		dev_priv->oa_pmu.event_state != I915_OA_EVENT_INIT) {
		spin_unlock(&dev_priv->oa_pmu.lock);
		return -EBUSY;
	}
	spin_unlock(&dev_priv->oa_pmu.lock);

	/*
	 * In case of multiple context mode, we need to check for
	 * CAP_SYS_ADMIN capability as we need to profile all the running
	 * contexts
	 */
	if (oa_attr.multiple_context_mode) {
		if (!capable(CAP_SYS_ADMIN))
			return -EACCES;
		dev_priv->oa_pmu.multiple_ctx_mode = true;
		if (oa_attr.sample_pid)
			dev_priv->oa_pmu.sample_info_flags |=
					I915_OA_SAMPLE_PID;
		if (oa_attr.sample_tag)
			dev_priv->oa_pmu.sample_info_flags |=
					I915_OA_SAMPLE_TAG;
	}

	report_format = oa_attr.format;
	dev_priv->oa_pmu.oa_buffer.format = report_format;
	if (oa_attr.multiple_context_mode)
		dev_priv->oa_pmu.oa_rcs_buffer.format = report_format;
	dev_priv->oa_pmu.metrics_set = oa_attr.metrics_set;

	if (IS_HASWELL(dev_priv->dev)) {
		int snapshot_size;

		if (report_format >= ARRAY_SIZE(hsw_perf_format_sizes))
			return -EINVAL;

		snapshot_size = hsw_perf_format_sizes[report_format];
		if (snapshot_size < 0)
			return -EINVAL;

		dev_priv->oa_pmu.oa_buffer.format_size = snapshot_size;
		if (oa_attr.multiple_context_mode)
			dev_priv->oa_pmu.oa_rcs_buffer.format_size =
					snapshot_size;

		if (oa_attr.metrics_set > I915_OA_METRICS_SET_MAX)
			return -EINVAL;
	} else {
		BUG(); /* pmu shouldn't have been registered */
		return -ENODEV;
	}


	/* Since we are limited to an exponential scale for
	 * programming the OA sampling period we don't allow userspace
	 * to pass a precise attr.sample_period. */
	if (event->attr.freq ||
	    (event->attr.sample_period != 0 &&
	     event->attr.sample_period != 1))
		return -EINVAL;

	dev_priv->oa_pmu.periodic = event->attr.sample_period;

	/* Instead of allowing userspace to configure the period via
	 * attr.sample_period we instead accept an exponent whereby
	 * the sample_period will be:
	 *
	 *   80ns * 2^(period_exponent + 1)
	 *
	 * Programming a period of 160 nanoseconds would not be very
	 * polite, so higher frequencies are reserved for root.
	 */
	if (dev_priv->oa_pmu.periodic) {
		u64 period_exponent = oa_attr.timer_exponent;

		if (period_exponent > 63)
			return -EINVAL;

		if (period_exponent < 15 && !capable(CAP_SYS_ADMIN))
			return -EACCES;

		dev_priv->oa_pmu.period_exponent = period_exponent;
	} else if (oa_attr.timer_exponent)
		return -EINVAL;

	/* We bypass the default perf core perf_paranoid_cpu() ||
	 * CAP_SYS_ADMIN check by using the PERF_PMU_CAP_IS_DEVICE
	 * flag and instead authenticate based on whether the current
	 * pid owns the specified context, or require CAP_SYS_ADMIN
	 * when collecting cross-context metrics.
	 */
	dev_priv->oa_pmu.specific_ctx = NULL;
	if (oa_attr.single_context) {
		u32 ctx_id = oa_attr.ctx_id;
		unsigned int drm_fd = oa_attr.drm_fd;
		struct fd fd = fdget(drm_fd);

		if (!fd.file)
			return -EBADF;

		dev_priv->oa_pmu.specific_ctx =
			lookup_context(dev_priv, fd.file, ctx_id);
		fdput(fd);

		if (!dev_priv->oa_pmu.specific_ctx)
			return -EINVAL;
	}

	if (!dev_priv->oa_pmu.specific_ctx &&
	    i915_oa_event_paranoid && !capable(CAP_SYS_ADMIN))
		return -EACCES;

	ret = init_oa_buffer(event);
	if (ret)
		return ret;

	if (oa_attr.multiple_context_mode) {
		ret = init_oa_rcs_buffer(event);
		if (ret)
			return ret;
	}

	BUG_ON(dev_priv->oa_pmu.exclusive_event);
	dev_priv->oa_pmu.exclusive_event = event;


	I915_WRITE(GDT_CHICKEN_BITS, GT_NOA_ENABLE);

	/* PRM:
	 *
	 * OA unit is using “crclk” for its functionality. When trunk
	 * level clock gating takes place, OA clock would be gated,
	 * unable to count the events from non-render clock domain.
	 * Render clock gating must be disabled when OA is enabled to
	 * count the events from non-render domain. Unit level clock
	 * gating for RCS should also be disabled.
	 */
	I915_WRITE(GEN7_MISCCPCTL, (I915_READ(GEN7_MISCCPCTL) &
				    ~GEN7_DOP_CLOCK_GATE_ENABLE));
	I915_WRITE(GEN6_UCGCTL1, (I915_READ(GEN6_UCGCTL1) |
				  GEN6_CSUNIT_CLOCK_GATE_DISABLE));

	event->destroy = i915_oa_event_destroy;

	/* PRM - observability performance counters:
	 *
	 *   OACONTROL, performance counter enable, note:
	 *
	 *   "When this bit is set, in order to have coherent counts,
	 *   RC6 power state and trunk clock gating must be disabled.
	 *   This can be achieved by programming MMIO registers as
	 *   0xA094=0 and 0xA090[31]=1"
	 *
	 *   In our case we are expected that taking pm + FORCEWAKE
	 *   references will effectively disable RC6 and trunk clock
	 *   gating.
	 */
	intel_runtime_pm_get(dev_priv);
	intel_uncore_forcewake_get(dev_priv, FORCEWAKE_ALL);

	return 0;
}

/* Note: Although pmu methods are called with the corresponding
 * perf_event_context lock taken (so we don't need to worry about our pmu
 * methods contending with each other) update_oacontrol() may be called
 * asynchronously via the i915_oa_pmu_[un]register() hooks.
 */
static void update_oacontrol(struct drm_i915_private *dev_priv)
{
	BUG_ON(!spin_is_locked(&dev_priv->oa_pmu.lock));

	if ((dev_priv->oa_pmu.event_state == I915_OA_EVENT_STARTED) ||
	(dev_priv->oa_pmu.event_state == I915_OA_EVENT_STOP_IN_PROGRESS)) {
		unsigned long ctx_id = 0;
		bool pinning_ok = false;

		if (dev_priv->oa_pmu.specific_ctx) {
			struct intel_context *ctx =
				dev_priv->oa_pmu.specific_ctx;
			struct drm_i915_gem_object *obj =
				ctx->legacy_hw_ctx.rcs_state;

			if (i915_gem_obj_is_pinned(obj)) {
				ctx_id = i915_gem_obj_ggtt_offset(obj);
				pinning_ok = true;
			}
		}

		if ((ctx_id == 0 || pinning_ok)) {
			bool periodic = dev_priv->oa_pmu.periodic;
			u32 period_exponent = dev_priv->oa_pmu.period_exponent;
			u32 report_format = dev_priv->oa_pmu.oa_buffer.format;

			I915_WRITE(GEN7_OACONTROL,
				   (ctx_id & GEN7_OACONTROL_CTX_MASK) |
				   (period_exponent <<
				    GEN7_OACONTROL_TIMER_PERIOD_SHIFT) |
				   (periodic ?
				    GEN7_OACONTROL_TIMER_ENABLE : 0) |
				   (report_format <<
				    GEN7_OACONTROL_FORMAT_SHIFT) |
				   (ctx_id ?
				    GEN7_OACONTROL_PER_CTX_ENABLE : 0) |
				   GEN7_OACONTROL_ENABLE);
			return;
		}
	}

	I915_WRITE(GEN7_OACONTROL, 0);
}

static void config_oa_regs(struct drm_i915_private *dev_priv,
			   const struct i915_oa_reg *regs,
			   int n_regs)
{
	int i;

	for (i = 0; i < n_regs; i++) {
		const struct i915_oa_reg *reg = regs + i;

		I915_WRITE(reg->addr, reg->value);
	}
}

static void i915_oa_event_start(struct perf_event *event, int flags)
{
	struct drm_i915_private *dev_priv =
		container_of(event->pmu, typeof(*dev_priv), oa_pmu.pmu);
	unsigned long lock_flags;
	u32 oastatus1, tail;

	if (dev_priv->oa_pmu.metrics_set == I915_OA_METRICS_SET_3D) {
		config_oa_regs(dev_priv, i915_oa_3d_mux_config_hsw,
				i915_oa_3d_mux_config_hsw_len);
		config_oa_regs(dev_priv, i915_oa_3d_b_counter_config_hsw,
				i915_oa_3d_b_counter_config_hsw_len);
	} else if (dev_priv->oa_pmu.metrics_set == I915_OA_METRICS_SET_COMPUTE) {
		config_oa_regs(dev_priv, i915_oa_compute_mux_config_hsw,
				i915_oa_compute_mux_config_hsw_len);
		config_oa_regs(dev_priv, i915_oa_compute_b_counter_config_hsw,
				i915_oa_compute_b_counter_config_hsw_len);
	} else if (dev_priv->oa_pmu.metrics_set == I915_OA_METRICS_SET_COMPUTE_EXTENDED) {
		config_oa_regs(dev_priv, i915_oa_compute_extended_mux_config_hsw,
				i915_oa_compute_extended_mux_config_hsw_len);
		config_oa_regs(dev_priv, i915_oa_compute_extended_b_counter_config_hsw,
				i915_oa_compute_extended_b_counter_config_hsw_len);
	} else if (dev_priv->oa_pmu.metrics_set == I915_OA_METRICS_SET_MEMORY_READS) {
		config_oa_regs(dev_priv, i915_oa_memory_reads_mux_config_hsw,
				i915_oa_memory_reads_mux_config_hsw_len);
		config_oa_regs(dev_priv, i915_oa_memory_reads_b_counter_config_hsw,
				i915_oa_memory_reads_b_counter_config_hsw_len);
	} else if (dev_priv->oa_pmu.metrics_set == I915_OA_METRICS_SET_MEMORY_WRITES) {
		config_oa_regs(dev_priv, i915_oa_memory_writes_mux_config_hsw,
				i915_oa_memory_writes_mux_config_hsw_len);
		config_oa_regs(dev_priv, i915_oa_memory_writes_b_counter_config_hsw,
				i915_oa_memory_writes_b_counter_config_hsw_len);
	} else if (dev_priv->oa_pmu.metrics_set == I915_OA_METRICS_SET_SAMPLER_BALANCE) {
		config_oa_regs(dev_priv, i915_oa_sampler_balance_mux_config_hsw,
				i915_oa_sampler_balance_mux_config_hsw_len);
		config_oa_regs(dev_priv, i915_oa_sampler_balance_b_counter_config_hsw,
				i915_oa_sampler_balance_b_counter_config_hsw_len);
	} else {
		/* XXX: On Haswell, when threshold disable mode is desired,
		 * instead of setting the threshold enable to '0', we need to
		 * program it to '1' and set OASTARTTRIG1 bits 15:0 to 0
		 * (threshold value of 0)
		 */
		I915_WRITE(OASTARTTRIG6, (OASTARTTRIG6_THRESHOLD_ENABLE |
					  OASTARTTRIG6_EVENT_SELECT_4));
		I915_WRITE(OASTARTTRIG5, 0); /* threshold value */

		I915_WRITE(OASTARTTRIG2, (OASTARTTRIG2_THRESHOLD_ENABLE |
					  OASTARTTRIG2_EVENT_SELECT_0));
		I915_WRITE(OASTARTTRIG1, 0); /* threshold value */

		/* Setup B0 as the gpu clock counter... */
		I915_WRITE(OACEC0_0, OACEC_COMPARE_GREATER_OR_EQUAL); /* to 0 */
		I915_WRITE(OACEC0_1, 0xfffe); /* Select NOA[0] */
	}

	spin_lock_irqsave(&dev_priv->oa_pmu.lock, lock_flags);

	dev_priv->oa_pmu.event_state = I915_OA_EVENT_STARTED;
	update_oacontrol(dev_priv);

	if (dev_priv->oa_pmu.multiple_ctx_mode)
		dev_priv->emit_profiling_data[I915_PROFILE_OA] =
				i915_oa_emit_perf_report;

	/* Reset the head ptr to ensure we don't forward reports relating
	 * to a previous perf event */
	oastatus1 = I915_READ(GEN7_OASTATUS1);
	tail = oastatus1 & GEN7_OASTATUS1_TAIL_MASK;
	I915_WRITE(GEN7_OASTATUS2, (tail & GEN7_OASTATUS2_HEAD_MASK) |
				    GEN7_OASTATUS2_GGTT);

	mmiowb();
	spin_unlock_irqrestore(&dev_priv->oa_pmu.lock, lock_flags);

	if (event->attr.sample_period)
		__hrtimer_start_range_ns(&dev_priv->oa_pmu.timer,
					 ns_to_ktime(PERIOD), 0,
					 HRTIMER_MODE_REL_PINNED, 0);

	event->hw.state = 0;
}

static void i915_oa_event_stop(struct perf_event *event, int flags)
{
	struct drm_i915_private *dev_priv =
		container_of(event->pmu, typeof(*dev_priv), oa_pmu.pmu);
	unsigned long lock_flags;

	if (event->attr.sample_period) {
		hrtimer_cancel(&dev_priv->oa_pmu.timer);
		if (dev_priv->oa_pmu.multiple_ctx_mode)
			schedule_work(&dev_priv->oa_pmu.forward_work);
		flush_oa_snapshots(dev_priv, false, U64_MAX);
	}

	if (dev_priv->oa_pmu.multiple_ctx_mode) {
		struct i915_oa_rcs_node *entry;

		spin_lock_irqsave(&dev_priv->oa_pmu.lock, lock_flags);

		dev_priv->emit_profiling_data[I915_PROFILE_OA] = NULL;
		dev_priv->oa_pmu.event_state = I915_OA_EVENT_STOP_IN_PROGRESS;
		list_for_each_entry(entry, &dev_priv->oa_pmu.node_list, head)
			entry->discard = true;

		spin_unlock_irqrestore(&dev_priv->oa_pmu.lock, lock_flags);
	} else {
		spin_lock_irqsave(&dev_priv->oa_pmu.lock, lock_flags);
		dev_priv->oa_pmu.event_state = I915_OA_EVENT_STOPPED;
		update_oacontrol(dev_priv);
		mmiowb();
		spin_unlock_irqrestore(&dev_priv->oa_pmu.lock, lock_flags);
	}
	event->hw.state = PERF_HES_STOPPED;
}

static int i915_oa_event_add(struct perf_event *event, int flags)
{
	if (flags & PERF_EF_START)
		i915_oa_event_start(event, flags);

	return 0;
}

static void i915_oa_event_del(struct perf_event *event, int flags)
{
	i915_oa_event_stop(event, flags);
}

static void i915_oa_event_read(struct perf_event *event)
{
	struct drm_i915_private *i915 =
		container_of(event->pmu, typeof(*i915), oa_pmu.pmu);

	/* XXX: What counter would be useful here? */
	local64_set(&event->count, 0);
}

static int i915_oa_event_flush(struct perf_event *event)
{
	if (event->attr.sample_period) {
		struct drm_i915_private *i915 =
			container_of(event->pmu, typeof(*i915), oa_pmu.pmu);
		int ret;

		if (i915->oa_pmu.multiple_ctx_mode) {
			ret = i915_oa_rcs_wait_gpu(i915);
			if (ret)
				return ret;
			forward_oa_rcs_snapshots(i915);
		} else
			flush_oa_snapshots(i915, true, U64_MAX);
	}

	return 0;
}

static int i915_oa_event_event_idx(struct perf_event *event)
{
	return 0;
}

static int i915_gen_event_init(struct perf_event *event)
{
	struct drm_i915_private *dev_priv =
		container_of(event->pmu, typeof(*dev_priv), gen_pmu.pmu);
	unsigned long lock_flags;
	int ret = 0;

	if (event->attr.type != event->pmu->type)
		return -ENOENT;

	/* To avoid the complexity of having to accurately filter
	 * data and marshal to the appropriate client
	 * we currently only allow exclusive access */
	spin_lock_irqsave(&dev_priv->gen_pmu.lock, lock_flags);
	if (dev_priv->gen_pmu.buffer.obj) {
		spin_unlock_irqrestore(&dev_priv->gen_pmu.lock, lock_flags);
		return -EBUSY;
	}
	spin_unlock_irqrestore(&dev_priv->gen_pmu.lock, lock_flags);

	/*
	 * We need to check for CAP_SYS_ADMIN capability as we profile all
	 * the running contexts
	 */
	if (!capable(CAP_SYS_ADMIN))
			return -EACCES;

	ret = init_gen_pmu_buffer(event);
	if (ret)
		return ret;

	BUG_ON(dev_priv->gen_pmu.exclusive_event);
	dev_priv->gen_pmu.exclusive_event = event;

	event->destroy = i915_gen_event_destroy;

	return 0;
}

static void i915_gen_event_start(struct perf_event *event, int flags)
{
	struct drm_i915_private *dev_priv =
		container_of(event->pmu, typeof(*dev_priv), gen_pmu.pmu);

	spin_lock(&dev_priv->gen_pmu.lock);
	dev_priv->gen_pmu.event_active = true;
	spin_unlock(&dev_priv->gen_pmu.lock);

	__hrtimer_start_range_ns(&dev_priv->gen_pmu.timer, ns_to_ktime(PERIOD),
					0, HRTIMER_MODE_REL_PINNED, 0);

	event->hw.state = 0;
}

static void i915_gen_event_stop(struct perf_event *event, int flags)
{
	struct drm_i915_private *dev_priv =
		container_of(event->pmu, typeof(*dev_priv), gen_pmu.pmu);
	struct i915_gen_pmu_node *entry;

	hrtimer_cancel(&dev_priv->gen_pmu.timer);
	schedule_work(&dev_priv->gen_pmu.forward_work);

	spin_lock(&dev_priv->gen_pmu.lock);
	dev_priv->gen_pmu.event_active = false;
	list_for_each_entry(entry, &dev_priv->gen_pmu.node_list, head)
		entry->discard = true;
	spin_unlock(&dev_priv->gen_pmu.lock);

	event->hw.state = PERF_HES_STOPPED;
}

static int i915_gen_event_add(struct perf_event *event, int flags)
{
	if (flags & PERF_EF_START)
		i915_gen_event_start(event, flags);

	return 0;
}

static void i915_gen_event_del(struct perf_event *event, int flags)
{
	i915_gen_event_stop(event, flags);
}

static void i915_gen_event_read(struct perf_event *event)
{
	struct drm_i915_private *i915 =
		container_of(event->pmu, typeof(*i915), gen_pmu.pmu);

	/* XXX: What counter would be useful here? */
	local64_set(&event->count, 0);
}

static int i915_gen_event_flush(struct perf_event *event)
{
	struct drm_i915_private *i915 =
		container_of(event->pmu, typeof(*i915), gen_pmu.pmu);
	int ret;

	ret = i915_gen_pmu_wait_gpu(i915);
	if (ret)
		return ret;

	forward_gen_pmu_snapshots(i915);
	return 0;
}

static int i915_gen_event_event_idx(struct perf_event *event)
{
	return 0;
}

void i915_oa_context_pin_notify(struct drm_i915_private *dev_priv,
				struct intel_context *context)
{
	unsigned long flags;

	if (dev_priv->oa_pmu.pmu.event_init == NULL)
		return;

	spin_lock_irqsave(&dev_priv->oa_pmu.lock, flags);

	if (dev_priv->oa_pmu.specific_ctx == context)
		update_oacontrol(dev_priv);

	mmiowb();
	spin_unlock_irqrestore(&dev_priv->oa_pmu.lock, flags);
}

void i915_oa_context_unpin_notify(struct drm_i915_private *dev_priv,
				  struct intel_context *context)
{
	unsigned long flags;

	if (dev_priv->oa_pmu.pmu.event_init == NULL)
		return;

	spin_lock_irqsave(&dev_priv->oa_pmu.lock, flags);

	if (dev_priv->oa_pmu.specific_ctx == context)
		update_oacontrol(dev_priv);

	mmiowb();
	spin_unlock_irqrestore(&dev_priv->oa_pmu.lock, flags);
}

static struct ctl_table oa_table[] = {
	{
	 .procname = "oa_event_paranoid",
	 .data = &i915_oa_event_paranoid,
	 .maxlen = sizeof(i915_oa_event_paranoid),
	 .mode = 0644,
	 .proc_handler = proc_dointvec,
	 },
	{}
};

static struct ctl_table i915_root[] = {
	{
	 .procname = "i915",
	 .maxlen = 0,
	 .mode = 0555,
	 .child = oa_table,
	 },
	{}
};

static struct ctl_table dev_root[] = {
	{
	 .procname = "dev",
	 .maxlen = 0,
	 .mode = 0555,
	 .child = i915_root,
	 },
	{}
};

void i915_oa_pmu_register(struct drm_device *dev)
{
	struct drm_i915_private *i915 = to_i915(dev);

	if (!IS_HASWELL(dev))
		return;

	i915->oa_pmu.sysctl_header = register_sysctl_table(dev_root);

	/* We need to be careful about forwarding cpu metrics to
	 * userspace considering that PERF_PMU_CAP_IS_DEVICE bypasses
	 * the events/core security check that stops an unprivileged
	 * process collecting metrics for other processes.
	 */
	i915->oa_pmu.dummy_regs = *task_pt_regs(current);

	hrtimer_init(&i915->oa_pmu.timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	i915->oa_pmu.timer.function = hrtimer_sample;

	INIT_WORK(&i915->oa_pmu.forward_work, forward_oa_rcs_work_fn);
	INIT_WORK(&i915->oa_pmu.event_destroy_work,
			i915_oa_rcs_event_destroy_work);

	spin_lock_init(&i915->oa_pmu.lock);

	i915->oa_pmu.pmu.capabilities  = PERF_PMU_CAP_IS_DEVICE;
	i915->oa_pmu.event_state = I915_OA_EVENT_INIT;

	/* Effectively disallow opening an event with a specific pid
	 * since we aren't interested in processes running on the cpu...
	 */
	i915->oa_pmu.pmu.task_ctx_nr   = perf_invalid_context;

	i915->oa_pmu.pmu.event_init    = i915_oa_event_init;
	i915->oa_pmu.pmu.add	       = i915_oa_event_add;
	i915->oa_pmu.pmu.del	       = i915_oa_event_del;
	i915->oa_pmu.pmu.start	       = i915_oa_event_start;
	i915->oa_pmu.pmu.stop	       = i915_oa_event_stop;
	i915->oa_pmu.pmu.read	       = i915_oa_event_read;
	i915->oa_pmu.pmu.flush	       = i915_oa_event_flush;
	i915->oa_pmu.pmu.event_idx     = i915_oa_event_event_idx;

	if (perf_pmu_register(&i915->oa_pmu.pmu, "i915_oa", -1))
		i915->oa_pmu.pmu.event_init = NULL;
}

void i915_oa_pmu_unregister(struct drm_device *dev)
{
	struct drm_i915_private *i915 = to_i915(dev);

	if (i915->oa_pmu.pmu.event_init == NULL)
		return;

	if (i915->oa_pmu.multiple_ctx_mode) {
		cancel_work_sync(&i915->oa_pmu.forward_work);
		cancel_work_sync(&i915->oa_pmu.event_destroy_work);
	}

	unregister_sysctl_table(i915->oa_pmu.sysctl_header);

	perf_pmu_unregister(&i915->oa_pmu.pmu);
	i915->oa_pmu.pmu.event_init = NULL;
}

void i915_gen_pmu_register(struct drm_device *dev)
{
	struct drm_i915_private *i915 = to_i915(dev);

	if (!(IS_HASWELL(dev) || IS_VALLEYVIEW(dev) || IS_BROADWELL(dev)))
		return;

	i915->gen_pmu.dummy_regs = *task_pt_regs(current);

	hrtimer_init(&i915->gen_pmu.timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	i915->gen_pmu.timer.function = hrtimer_sample_gen;

	INIT_WORK(&i915->gen_pmu.forward_work, forward_gen_pmu_work_fn);
	INIT_WORK(&i915->gen_pmu.event_destroy_work,
			i915_gen_pmu_event_destroy_work);

	spin_lock_init(&i915->gen_pmu.lock);

	i915->gen_pmu.pmu.capabilities  = PERF_PMU_CAP_IS_DEVICE;

	/* Effectively disallow opening an event with a specific pid
	 * since we aren't interested in processes running on the cpu...
	 */
	i915->gen_pmu.pmu.task_ctx_nr   = perf_invalid_context;

	i915->gen_pmu.pmu.event_init    = i915_gen_event_init;
	i915->gen_pmu.pmu.add	       = i915_gen_event_add;
	i915->gen_pmu.pmu.del	       = i915_gen_event_del;
	i915->gen_pmu.pmu.start	       = i915_gen_event_start;
	i915->gen_pmu.pmu.stop	       = i915_gen_event_stop;
	i915->gen_pmu.pmu.read	       = i915_gen_event_read;
	i915->gen_pmu.pmu.flush	       = i915_gen_event_flush;
	i915->gen_pmu.pmu.event_idx     = i915_gen_event_event_idx;

	if (perf_pmu_register(&i915->gen_pmu.pmu, "i915_gen", -1))
		i915->gen_pmu.pmu.event_init = NULL;
}

void i915_gen_pmu_unregister(struct drm_device *dev)
{
	struct drm_i915_private *i915 = to_i915(dev);

	if (i915->gen_pmu.pmu.event_init == NULL)
		return;

	cancel_work_sync(&i915->gen_pmu.forward_work);
	cancel_work_sync(&i915->gen_pmu.event_destroy_work);

	perf_pmu_unregister(&i915->gen_pmu.pmu);
	i915->gen_pmu.pmu.event_init = NULL;
}
