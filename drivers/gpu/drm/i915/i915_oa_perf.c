#include <linux/perf_event.h>
#include <linux/sizes.h>

#include "i915_drv.h"
#include "intel_ringbuffer.h"

/* Must be a power of two */
#define OA_BUFFER_SIZE	     SZ_16M
#define OA_TAKEN(tail, head) ((tail - head) & (OA_BUFFER_SIZE - 1))

#define FREQUENCY 200
#define PERIOD max_t(u64, 10000, NSEC_PER_SEC / FREQUENCY)

static int hsw_perf_format_sizes[] = {
	64,  /* A13_HSW */
	128, /* A29_HSW */
	128, /* A13_B8_C8_HSW */

	/* XXX: If we were to disallow this format we could avoid needing to
	 * handle snapshots being split in two when they don't factor into
	 * the buffer size... */
	192, /* A29_B8_C8_HSW */
	64,  /* B4_C8_HSW */
	256, /* A45_B8_C8_HSW */
	128, /* B4_C8_A16_HSW */
	64   /* C4_B8_HSW */
};

static void forward_one_oa_snapshot_to_event(struct drm_i915_private *dev_priv,
					     u8 *snapshot,
					     struct perf_event *event)
{
	struct perf_sample_data data;
	int snapshot_size = dev_priv->oa_pmu.oa_buffer.format_size;
	struct perf_raw_record raw;

	perf_sample_data_init(&data, 0, event->hw.last_period);

	/* XXX: It seems strange that kernel/events/core.c only initialises
	 * data->type if event->attr.sample_id_all is set
	 *
	 * For now, we explicitly set this otherwise perf_event_overflow()
	 * may reference an uninitialised sample_type and may not actually
	 * forward our raw data.
	 */
	data.type = event->attr.sample_type;

	/* Note: the 32 bit size + raw data must be 8 byte aligned.
	 *
	 * So that we don't have to first copy the data out of the
	 * OABUFFER, we instead allow an overrun and forward the 32 bit
	 * report id of the next snapshot...
	 */
	raw.size = snapshot_size + 4;
	raw.data = snapshot;

	data.raw = &raw;

	perf_event_overflow(event, &data, &dev_priv->oa_pmu.dummy_regs);
}

static u32 forward_oa_snapshots(struct drm_i915_private *dev_priv,
				u32 head,
				u32 tail)
{
	struct perf_event *exclusive_event = dev_priv->oa_pmu.exclusive_event;
	int snapshot_size = dev_priv->oa_pmu.oa_buffer.format_size;
	u8 *oa_buf_base = dev_priv->oa_pmu.oa_buffer.addr;
	u32 mask = (OA_BUFFER_SIZE - 1);
	u8 scratch[snapshot_size + 4];
	u8 *snapshot;
	u32 taken;

	head -= dev_priv->oa_pmu.oa_buffer.gtt_offset;
	tail -= dev_priv->oa_pmu.oa_buffer.gtt_offset;

	/* Note: the gpu doesn't wrap the tail according to the OA buffer size
	 * so when we need to make sure our head/tail values are in-bounds we
	 * use the above mask.
	 */

	while ((taken = OA_TAKEN(tail, head))) {
		u32 before;

		/* The tail increases in 64 byte increments, not in
		 * format_size steps. */
		if (taken < snapshot_size)
			break;

		/* As well as handling snapshots that are split in two we also
		 * need to pad snapshots at the end of the oabuffer so that
		 * forward_one_oa_snapshot_to_event() can safely overrun by 4
		 * bytes for alignment. */
		before = OA_BUFFER_SIZE - (head & mask);
		if (before <= snapshot_size) {
			u32 after = snapshot_size - before;

			memcpy(scratch, oa_buf_base + (head & mask), before);
			if (after)
				memcpy(scratch + before, oa_buf_base, after);
			snapshot = scratch;
		} else
			snapshot = oa_buf_base + (head & mask);

		head += snapshot_size;

		/* We currently only allow exclusive access to the counters
		 * so only have one event to forward too... */
		if (exclusive_event->state == PERF_EVENT_STATE_ACTIVE)
			forward_one_oa_snapshot_to_event(dev_priv, snapshot,
							 exclusive_event);
	}

	return dev_priv->oa_pmu.oa_buffer.gtt_offset + head;
}

static void flush_oa_snapshots(struct drm_i915_private *dev_priv,
			       bool force_wake)
{
	unsigned long flags;
	u32 oastatus2;
	u32 oastatus1;
	u32 head;
	u32 tail;

	/* Can either flush via hrtimer callback or pmu methods/fops */
	if (!force_wake) {

		/* If the hrtimer triggers at the same time that we are
		 * responding to a userspace initiated flush then we can
		 * just bail out...
		 *
		 * FIXME: strictly this lock doesn't imply we are already
		 * flushing though it shouldn't really be a problem to skip
		 * the odd hrtimer flush anyway.
		 */
		if (!spin_trylock_irqsave(&dev_priv->oa_pmu.lock, flags))
			return;
	} else
		spin_lock_irqsave(&dev_priv->oa_pmu.lock, flags);

	WARN_ON(!dev_priv->oa_pmu.oa_buffer.addr);

	oastatus2 = I915_READ(OASTATUS2);
	oastatus1 = I915_READ(OASTATUS1);

	head = oastatus2 & OASTATUS2_HEAD_MASK;
	tail = oastatus1 & OASTATUS1_TAIL_MASK;

	if (oastatus1 & (OASTATUS1_OABUFFER_OVERFLOW |
			 OASTATUS1_REPORT_LOST)) {

		/* XXX: How can we convey report-lost errors to userspace?  It
		 * doesn't look like perf's _REPORT_LOST mechanism is
		 * appropriate in this case; that's just for cases where we
		 * run out of space for samples in the perf circular buffer.
		 *
		 * Maybe we can claim a special report-id and use that to
		 * forward status flags?
		 */
		pr_debug("OA buffer read error: addr = %p, head = %u, offset = %u, tail = %u cnt o'flow = %d, buf o'flow = %d, rpt lost = %d\n",
			 dev_priv->oa_pmu.oa_buffer.addr,
			 head,
			 head - dev_priv->oa_pmu.oa_buffer.gtt_offset,
			 tail,
			 oastatus1 & OASTATUS1_COUNTER_OVERFLOW ? 1 : 0,
			 oastatus1 & OASTATUS1_OABUFFER_OVERFLOW ? 1 : 0,
			 oastatus1 & OASTATUS1_REPORT_LOST ? 1 : 0);

		I915_WRITE(OASTATUS1, oastatus1 &
			   ~(OASTATUS1_OABUFFER_OVERFLOW |
			     OASTATUS1_REPORT_LOST));
	}

	head = forward_oa_snapshots(dev_priv, head, tail);

	I915_WRITE(OASTATUS2, (head & OASTATUS2_HEAD_MASK) | OASTATUS2_GGTT);

	spin_unlock_irqrestore(&dev_priv->oa_pmu.lock, flags);
}

static void
oa_buffer_free(struct kref *kref)
{
	struct drm_i915_private *i915 =
		container_of(kref, typeof(*i915), oa_pmu.oa_buffer.refcount);

	BUG_ON(!mutex_is_locked(&i915->dev->struct_mutex));

	vunmap(i915->oa_pmu.oa_buffer.addr);
	i915_gem_object_ggtt_unpin(i915->oa_pmu.oa_buffer.obj);
	drm_gem_object_unreference(&i915->oa_pmu.oa_buffer.obj->base);

	i915->oa_pmu.oa_buffer.obj = NULL;
	i915->oa_pmu.oa_buffer.gtt_offset = 0;
	i915->oa_pmu.oa_buffer.addr = NULL;
}

static inline void oa_buffer_reference(struct drm_i915_private *i915)
{
	kref_get(&i915->oa_pmu.oa_buffer.refcount);
}

static void oa_buffer_unreference(struct drm_i915_private *i915)
{
	WARN_ON(!i915->oa_pmu.oa_buffer.obj);

	kref_put(&i915->oa_pmu.oa_buffer.refcount, oa_buffer_free);
}

static void i915_oa_event_destroy(struct perf_event *event)
{
	struct drm_i915_private *i915 =
		container_of(event->pmu, typeof(*i915), oa_pmu.pmu);

	WARN_ON(event->parent);

	mutex_lock(&i915->dev->struct_mutex);

	oa_buffer_unreference(i915);

	if (i915->oa_pmu.specific_ctx) {
		struct drm_i915_gem_object *obj;

		obj = i915->oa_pmu.specific_ctx->legacy_hw_ctx.rcs_state;
		if (i915_gem_obj_is_pinned(obj))
			i915_gem_object_ggtt_unpin(obj);
		i915->oa_pmu.specific_ctx = NULL;
	}

	BUG_ON(i915->oa_pmu.exclusive_event != event);
	i915->oa_pmu.exclusive_event = NULL;

	mutex_unlock(&i915->dev->struct_mutex);

	gen6_gt_force_wake_put(i915, FORCEWAKE_ALL);
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
	BUG_ON(!mutex_is_locked(&dev_priv->dev->struct_mutex));
	BUG_ON(dev_priv->oa_pmu.oa_buffer.obj);

	kref_init(&dev_priv->oa_pmu.oa_buffer.refcount);

	bo = i915_gem_alloc_object(dev_priv->dev, OA_BUFFER_SIZE);
	if (bo == NULL) {
		DRM_ERROR("Failed to allocate OA buffer\n");
		ret = -ENOMEM;
		goto err;
	}
	dev_priv->oa_pmu.oa_buffer.obj = bo;

	ret = i915_gem_object_set_cache_level(bo, I915_CACHE_LLC);
	if (ret)
		goto err_unref;

	/* PreHSW required 512K alignment, HSW requires 16M */
	ret = i915_gem_obj_ggtt_pin(bo, SZ_16M, 0);
	if (ret)
		goto err_unref;

	dev_priv->oa_pmu.oa_buffer.gtt_offset = i915_gem_obj_ggtt_offset(bo);
	dev_priv->oa_pmu.oa_buffer.addr = vmap_oa_buffer(bo);

	/* Pre-DevBDW: OABUFFER must be set with counters off,
	 * before OASTATUS1, but after OASTATUS2 */
	I915_WRITE(OASTATUS2, dev_priv->oa_pmu.oa_buffer.gtt_offset |
		   OASTATUS2_GGTT); /* head */
	I915_WRITE(GEN7_OABUFFER, dev_priv->oa_pmu.oa_buffer.gtt_offset);
	I915_WRITE(OASTATUS1, dev_priv->oa_pmu.oa_buffer.gtt_offset |
		   OASTATUS1_OABUFFER_SIZE_16M); /* tail */

	DRM_DEBUG_DRIVER("OA Buffer initialized, gtt offset = 0x%x, vaddr = %p",
			 dev_priv->oa_pmu.oa_buffer.gtt_offset,
			 dev_priv->oa_pmu.oa_buffer.addr);

	return 0;

err_unref:
	drm_gem_object_unreference_unlocked(&bo->base);
err:
	return ret;
}

static enum hrtimer_restart hrtimer_sample(struct hrtimer *hrtimer)
{
	struct drm_i915_private *i915 =
		container_of(hrtimer, typeof(*i915), oa_pmu.timer);

	flush_oa_snapshots(i915, false);

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

static int i915_oa_event_init(struct perf_event *event)
{
	struct perf_event_context *ctx = event->ctx;
	struct drm_i915_private *dev_priv =
		container_of(event->pmu, typeof(*dev_priv), oa_pmu.pmu);
	int ret = 0;

	if (event->attr.type != event->pmu->type)
		return -ENOENT;

	/* When tracing a specific pid events/core will enable/disable
	 * the event only while that pid is running on a cpu but that
	 * doesn't really make sense here. */
	if (ctx) {
		if (ctx->task)
			return -EINVAL;
	}
#if 0
	else
	    pr_err("Unexpected NULL perf_event_context\n");

	 /* XXX: it looks like we get a NULL ctx, so check if setting
	  * pmu->task_ctx_nr to perf_invalid_context in _pmu_register
	  * implies events/core.c will also implicitly disallow
	  * associating a perf_oa event with a task?
	  */
#endif

	/* To avoid the complexity of having to accurately filter
	 * counter snapshots and marshal to the appropriate client
	 * we currently only allow exclusive access */
	if (dev_priv->oa_pmu.oa_buffer.obj)
		return -EBUSY;

	/* TODO: improve cooperation with the cmd_parser which provides
	 * another mechanism for enabling the OA counters. */
	if (I915_READ(OACONTROL) & OACONTROL_ENABLE)
		return -EBUSY;

	/* Since we are limited to an exponential scale for
	 * programming the OA sampling period we don't allow userspace
	 * to pass a precise attr.sample_period. */
	if (event->attr.freq ||
	    (event->attr.sample_period != 0 &&
	     event->attr.sample_period != 1))
		return -EINVAL;

	/* Instead of allowing userspace to configure the period via
	 * attr.sample_period we instead accept an exponent whereby
	 * the sample_period will be:
	 *
	 *   80ns * 2^(period_exponent + 1)
	 *
	 * Programming a period of 160 nanoseconds would not be very
	 * polite, so higher frequencies are reserved for root.
	 */
	if (event->attr.sample_period) {
		u64 period_exponent =
			event->attr.config & I915_PERF_OA_TIMER_EXPONENT_MASK;
		period_exponent >>= I915_PERF_OA_TIMER_EXPONENT_SHIFT;

		if (period_exponent < 15 && !capable(CAP_SYS_ADMIN))
			return -EACCES;
	}

	if (!IS_HASWELL(dev_priv->dev))
		return -ENODEV;

	/* We bypass the default perf core perf_paranoid_cpu() ||
	 * CAP_SYS_ADMIN check by using the PERF_PMU_CAP_IS_DEVICE
	 * flag and instead authenticate based on whether the current
	 * pid owns the specified context, or require CAP_SYS_ADMIN
	 * when collecting cross-context metrics.
	 */
	dev_priv->oa_pmu.specific_ctx = NULL;
	if (event->attr.config & I915_PERF_OA_SINGLE_CONTEXT_ENABLE) {
		u32 ctx_id = event->attr.config & I915_PERF_OA_CTX_ID_MASK;
		unsigned int drm_fd = event->attr.config1;
		struct fd fd = fdget(drm_fd);

		if (fd.file) {
			dev_priv->oa_pmu.specific_ctx =
				lookup_context(dev_priv, fd.file, ctx_id);
		}
	}

	if (!dev_priv->oa_pmu.specific_ctx && !capable(CAP_SYS_ADMIN))
		return -EACCES;

	mutex_lock(&dev_priv->dev->struct_mutex);

	/* XXX: Not sure that this is really acceptable...
	 *
	 * i915_gem_context.c currently owns pinning/unpinning legacy
	 * context buffers and although that code has a
	 * get_context_alignment() func to handle a different
	 * constraint for gen6 we are assuming it's fixed for gen7
	 * here. Another option besides pinning here would be to
	 * instead hook into context switching and update the
	 * OACONTROL configuration on the fly.
	 */
	if (dev_priv->oa_pmu.specific_ctx) {
		struct intel_context *ctx = dev_priv->oa_pmu.specific_ctx;
		int ret;

		ret = i915_gem_obj_ggtt_pin(ctx->legacy_hw_ctx.rcs_state,
					    4096, 0);
		if (ret) {
			DRM_DEBUG_DRIVER("Couldn't pin %d\n", ret);
			ret = -EBUSY;
			goto err;
		}
	}

	if (!dev_priv->oa_pmu.oa_buffer.obj)
		ret = init_oa_buffer(event);
	else
		oa_buffer_reference(dev_priv);

	if (ret)
		goto err;

	BUG_ON(dev_priv->oa_pmu.exclusive_event);
	dev_priv->oa_pmu.exclusive_event = event;

	event->destroy = i915_oa_event_destroy;

	mutex_unlock(&dev_priv->dev->struct_mutex);

	/* PRM - observability performance counters:
	 *
	 *   OACONTROL, performance counter enable, note:
	 *
	 *   "When this bit is set, in order to have coherent counts,
	 *   RC6 power state and trunk clock gating must be disabled.
	 *   This can be achieved by programming MMIO registers as
	 *   0xA094=0 and 0xA090[31]=1"
	 *
	 *   0xA094 corresponds to GEN6_RC_STATE
	 *   0xA090[31] corresponds to GEN6_RC_CONTROL, GEN6_RC_CTL_HW_ENABLE
	 */
	/* XXX: We should probably find a more refined way of disabling RC6
	 * in cooperation with intel_pm.c.
	 * TODO: Find a way to disable clock gating too
	 */
	gen6_gt_force_wake_get(dev_priv, FORCEWAKE_ALL);

	return 0;

err:
	mutex_unlock(&dev_priv->dev->struct_mutex);

	return ret;
}

static void i915_oa_event_start(struct perf_event *event, int flags)
{
	struct drm_i915_private *dev_priv =
		container_of(event->pmu, typeof(*dev_priv), oa_pmu.pmu);
	u64 report_format;
	int snapshot_size;
	unsigned long ctx_id;
	u64 period_exponent;

	/* PRM - observability performance counters:
	 *
	 *   OACONTROL, specific context enable:
	 *
	 *   "OA unit level clock gating must be ENABLED when using
	 *   specific ContextID feature."
	 *
	 * Assuming we don't ever disable OA unit level clock gating
	 * lets just assert that this condition is met...
	 */
	WARN_ONCE(I915_READ(GEN6_UCGCTL3) & GEN6_OACSUNIT_CLOCK_GATE_DISABLE,
		  "disabled OA unit level clock gating will result in incorrect per-context OA counters");

	/* XXX: On Haswell, when threshold disable mode is desired,
	 * instead of setting the threshold enable to '0', we need to
	 * program it to '1' and set OASTARTTRIG1 bits 15:0 to 0
	 * (threshold value of 0)
	 */
	I915_WRITE(OASTARTTRIG6, (OASTARTTRIG6_B4_TO_B7_THRESHOLD_ENABLE |
				  OASTARTTRIG6_B4_CUSTOM_EVENT_ENABLE));
	I915_WRITE(OASTARTTRIG5, 0); /* threshold value */

	I915_WRITE(OASTARTTRIG2, (OASTARTTRIG2_B0_TO_B3_THRESHOLD_ENABLE |
				  OASTARTTRIG2_B0_CUSTOM_EVENT_ENABLE));
	I915_WRITE(OASTARTTRIG1, 0); /* threshold value */

	/* Setup B0 as the gpu clock counter... */
	I915_WRITE(OACEC0_0, OACEC0_0_B0_COMPARE_GREATER_OR_EQUAL); /* to 0 */
	I915_WRITE(OACEC0_1, 0xfffe); /* Select NOA[0] */

	period_exponent = event->attr.config & I915_PERF_OA_TIMER_EXPONENT_MASK;
	period_exponent >>= I915_PERF_OA_TIMER_EXPONENT_SHIFT;

	if (dev_priv->oa_pmu.specific_ctx) {
		struct intel_context *ctx = dev_priv->oa_pmu.specific_ctx;

		ctx_id = i915_gem_obj_ggtt_offset(ctx->legacy_hw_ctx.rcs_state);
	} else
		ctx_id = 0;

	report_format = event->attr.config & I915_PERF_OA_FORMAT_MASK;
	report_format >>= I915_PERF_OA_FORMAT_SHIFT;
	snapshot_size = hsw_perf_format_sizes[report_format];

	I915_WRITE(OACONTROL,  0 |
		   (ctx_id & OACONTROL_CTX_MASK) |
		   period_exponent << OACONTROL_TIMER_PERIOD_SHIFT |
		   (event->attr.sample_period ? OACONTROL_TIMER_ENABLE : 0) |
		   report_format << OACONTROL_FORMAT_SHIFT|
		   (ctx_id ? OACONTROL_PER_CTX_ENABLE : 0) |
		   OACONTROL_ENABLE);

	if (event->attr.sample_period) {
		__hrtimer_start_range_ns(&dev_priv->oa_pmu.timer,
					 ns_to_ktime(PERIOD), 0,
					 HRTIMER_MODE_REL_PINNED, 0);
	}

	dev_priv->oa_pmu.oa_buffer.format = report_format;
	dev_priv->oa_pmu.oa_buffer.format_size = snapshot_size;

	event->hw.state = 0;
}

static void i915_oa_event_stop(struct perf_event *event, int flags)
{
	struct drm_i915_private *dev_priv =
		container_of(event->pmu, typeof(*dev_priv), oa_pmu.pmu);

	I915_WRITE(OACONTROL, I915_READ(OACONTROL) & ~OACONTROL_ENABLE);

	if (event->attr.sample_period) {
		hrtimer_cancel(&dev_priv->oa_pmu.timer);
		flush_oa_snapshots(dev_priv, true);
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

	/* We want userspace to be able to use a read() to explicitly
	 * flush OA counter snapshots... */
	if (event->attr.sample_period)
		flush_oa_snapshots(i915, true);

	/* XXX: What counter would be useful here? */
	local64_set(&event->count, 0);
}

static int i915_oa_event_event_idx(struct perf_event *event)
{
	return 0;
}

void i915_oa_pmu_register(struct drm_device *dev)
{
	struct drm_i915_private *i915 = to_i915(dev);

	/* We need to be careful about forwarding cpu metrics to
	 * userspace considering that PERF_PMU_CAP_IS_DEVICE bypasses
	 * the events/core security check that stops an unprivileged
	 * process collecting metrics for other processes.
	 */
	i915->oa_pmu.dummy_regs = *task_pt_regs(current);

	hrtimer_init(&i915->oa_pmu.timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	i915->oa_pmu.timer.function = hrtimer_sample;

	spin_lock_init(&i915->oa_pmu.lock);

	i915->oa_pmu.pmu.capabilities  = PERF_PMU_CAP_IS_DEVICE;
	i915->oa_pmu.pmu.task_ctx_nr   = perf_invalid_context;
	i915->oa_pmu.pmu.event_init    = i915_oa_event_init;
	i915->oa_pmu.pmu.add	       = i915_oa_event_add;
	i915->oa_pmu.pmu.del	       = i915_oa_event_del;
	i915->oa_pmu.pmu.start	       = i915_oa_event_start;
	i915->oa_pmu.pmu.stop	       = i915_oa_event_stop;
	i915->oa_pmu.pmu.read	       = i915_oa_event_read;
	i915->oa_pmu.pmu.event_idx     = i915_oa_event_event_idx;

	if (perf_pmu_register(&i915->oa_pmu.pmu, "i915_oa", -1))
		i915->oa_pmu.pmu.event_init = NULL;
}

void i915_oa_pmu_unregister(struct drm_device *dev)
{
	struct drm_i915_private *i915 = to_i915(dev);

	if (i915->oa_pmu.pmu.event_init == NULL)
		return;

	perf_pmu_unregister(&i915->oa_pmu.pmu);
	i915->oa_pmu.pmu.event_init = NULL;
}
