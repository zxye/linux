#include <linux/perf_event.h>
#include <linux/sizes.h>

#include "i915_drv.h"
#include "intel_ringbuffer.h"

/* Must be a power of two */
#define OA_BUFFER_SIZE	     SZ_16M
#define OA_TAKEN(tail, head) ((tail - head) & (OA_BUFFER_SIZE - 1))

#define FREQUENCY 200
#define PERIOD max_t(u64, 10000, NSEC_PER_SEC / FREQUENCY)

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

static int bdw_perf_format_sizes[] = {
	64,  /* A12_BDW */
	-1,  /* invalid */
	128, /* A12_B8_C8_BDW */
	-1,  /* invalid */
	-1,  /* invalid */
	256, /* A36_B8_C8_BDW */
	-1,  /* invalid */
	64,  /* C4_B8_BDW */
};

/* A generated mux config to select counters useful for profiling 3D
 * workloads */
static struct i915_oa_reg hsw_profile_3d_mux_config[] = {

	{ 0x253A4, 0x01600000 },
	{ 0x25440, 0x00100000 },
	{ 0x25128, 0x00000000 },
	{ 0x2691C, 0x00000800 },
	{ 0x26AA0, 0x01500000 },
	{ 0x26B9C, 0x00006000 },
	{ 0x2791C, 0x00000800 },
	{ 0x27AA0, 0x01500000 },
	{ 0x27B9C, 0x00006000 },
	{ 0x2641C, 0x00000400 },
	{ 0x25380, 0x00000010 },
	{ 0x2538C, 0x00000000 },
	{ 0x25384, 0x0800AAAA },
	{ 0x25400, 0x00000004 },
	{ 0x2540C, 0x06029000 },
	{ 0x25410, 0x00000002 },
	{ 0x25404, 0x5C30FFFF },
	{ 0x25100, 0x00000016 },
	{ 0x25110, 0x00000400 },
	{ 0x25104, 0x00000000 },
	{ 0x26804, 0x00001211 },
	{ 0x26884, 0x00000100 },
	{ 0x26900, 0x00000002 },
	{ 0x26908, 0x00700000 },
	{ 0x26904, 0x00000000 },
	{ 0x26984, 0x00001022 },
	{ 0x26A04, 0x00000011 },
	{ 0x26A80, 0x00000006 },
	{ 0x26A88, 0x00000C02 },
	{ 0x26A84, 0x00000000 },
	{ 0x26B04, 0x00001000 },
	{ 0x26B80, 0x00000002 },
	{ 0x26B8C, 0x00000007 },
	{ 0x26B84, 0x00000000 },
	{ 0x27804, 0x00004844 },
	{ 0x27884, 0x00000400 },
	{ 0x27900, 0x00000002 },
	{ 0x27908, 0x0E000000 },
	{ 0x27904, 0x00000000 },
	{ 0x27984, 0x00004088 },
	{ 0x27A04, 0x00000044 },
	{ 0x27A80, 0x00000006 },
	{ 0x27A88, 0x00018040 },
	{ 0x27A84, 0x00000000 },
	{ 0x27B04, 0x00004000 },
	{ 0x27B80, 0x00000002 },
	{ 0x27B8C, 0x000000E0 },
	{ 0x27B84, 0x00000000 },
	{ 0x26104, 0x00002222 },
	{ 0x26184, 0x0C006666 },
	{ 0x26284, 0x04000000 },
	{ 0x26304, 0x04000000 },
	{ 0x26400, 0x00000002 },
	{ 0x26410, 0x000000A0 },
	{ 0x26404, 0x00000000 },
	{ 0x25420, 0x04108020 },
	{ 0x25424, 0x1284A420 },
	{ 0x2541C, 0x00000000 },
	{ 0x25428, 0x00042049 },
};

/* A corresponding B counter configuration for profiling 3D workloads */
static struct i915_oa_reg hsw_profile_3d_b_counter_config[] = {
	{ 0x2724, 0x00800000 },
	{ 0x2720, 0x00000000 },
	{ 0x2714, 0x00800000 },
	{ 0x2710, 0x00000000 },
};

static struct i915_oa_reg bdw_profile_3d_noa_slice0_mux_config[] = {
	{ 0x9840, 0x000000A0 },
	{ 0x9888, 0x143F000F },
	{ 0x9888, 0x14110014 },
	{ 0x9888, 0x14310014 },
	{ 0x9888, 0x14BF000F },
	{ 0x9888, 0x13837BE0 },
	{ 0x9888, 0x3B800060 },
	{ 0x9888, 0x3D800005 },
	{ 0x9888, 0x005C4000 },
	{ 0x9888, 0x065C8000 },
	{ 0x9888, 0x085CC000 },
	{ 0x9888, 0x003D8000 },
	{ 0x9888, 0x183D0800 },
	{ 0x9888, 0x0A3F0023 },
	{ 0x9888, 0x103F0000 },
	{ 0x9888, 0x00584000 },
	{ 0x9888, 0x08584000 },
	{ 0x9888, 0x0A5A4000 },
	{ 0x9888, 0x005B4000 },
	{ 0x9888, 0x0E5B8000 },
	{ 0x9888, 0x185B2400 },
	{ 0x9888, 0x0A1D4000 },
	{ 0x9888, 0x0C1F0800 },
	{ 0x9888, 0x0E1FAA00 },
	{ 0x9888, 0x00384000 },
	{ 0x9888, 0x0E384000 },
	{ 0x9888, 0x16384000 },
	{ 0x9888, 0x18380001 },
	{ 0x9888, 0x00392000 },
	{ 0x9888, 0x06398000 },
	{ 0x9888, 0x0839A000 },
	{ 0x9888, 0x0A391000 },
	{ 0x9888, 0x00104000 },
	{ 0x9888, 0x08104000 },
	{ 0x9888, 0x00110030 },
	{ 0x9888, 0x08110031 },
	{ 0x9888, 0x10110000 },
	{ 0x9888, 0x00134000 },
	{ 0x9888, 0x16130020 },
	{ 0x9888, 0x06308000 },
	{ 0x9888, 0x08308000 },
	{ 0x9888, 0x06311800 },
	{ 0x9888, 0x08311880 },
	{ 0x9888, 0x10310000 },
	{ 0x9888, 0x0E334000 },
	{ 0x9888, 0x16330080 },
	{ 0x9888, 0x0ABF1180 },
	{ 0x9888, 0x10BF0000 },
	{ 0x9888, 0x0ADA8000 },
	{ 0x9888, 0x0A9D8000 },
	{ 0x9888, 0x109F0002 },
	{ 0x9888, 0x0AB94000 },
	{ 0x9888, 0x0D888000 },
	{ 0x9888, 0x018A8000 },
	{ 0x9888, 0x0F8A8000 },
	{ 0x9888, 0x198A8000 },
	{ 0x9888, 0x1B8A00A0 },
	{ 0x9888, 0x238B0020 },
	{ 0x9888, 0x258B2550 },
	{ 0x9888, 0x198C1000 },
	{ 0x9888, 0x0B8D8000 },
	{ 0x9888, 0x1F85AA80 },
	{ 0x9888, 0x2185AAA0 },
	{ 0x9888, 0x2385002A },
	{ 0x9888, 0x0D831021 },
	{ 0x9888, 0x0F83572F },
	{ 0x9888, 0x01835680 },
	{ 0x9888, 0x038315AC },
	{ 0x9888, 0x0583002A },
	{ 0x9888, 0x11830000 },
	{ 0x9888, 0x19835400 },
	{ 0x9888, 0x1B830001 },
	{ 0x9888, 0x07830000 },
	{ 0x9888, 0x09830000 },
	{ 0x9888, 0x0184C000 },
	{ 0x9888, 0x07848000 },
	{ 0x9888, 0x0984C000 },
	{ 0x9888, 0x0B84C000 },
	{ 0x9888, 0x0D84C000 },
	{ 0x9888, 0x0F84C000 },
	{ 0x9888, 0x0384C000 },
	{ 0x9888, 0x05844000 },
	{ 0x9888, 0x1B80C137 },
	{ 0x9888, 0x1D80C147 },
	{ 0x9888, 0x21800000 },
	{ 0x9888, 0x1180C000 },
	{ 0x9888, 0x17808000 },
	{ 0x9888, 0x1980C000 },
	{ 0x9888, 0x1F80C000 },
	{ 0x9888, 0x1380C000 },
	{ 0x9888, 0x15804000 },
	{ 0x0D24, 0x00000000 },
	{ 0x9888, 0x4D801110 },
	{ 0x9888, 0x4F800331 },
	{ 0x9888, 0x43800802 },
	{ 0x9888, 0x51800000 },
	{ 0x9888, 0x45801465 },
	{ 0x9888, 0x53801111 },
	{ 0x9888, 0x478014A5 },
	{ 0x9888, 0x31800000 },
	{ 0x9888, 0x3F8014A5 },
	{ 0x9888, 0x41800005 },
	{ 0x9840, 0x00000080 },
};

static struct i915_oa_reg bdw_profile_3d_noa_slice1_mux_config[] = {
	{ 0x9840, 0x000000A0 },
	{ 0x9888, 0x143F000F },
	{ 0x9888, 0x14BF000F },
	{ 0x9888, 0x14910014 },
	{ 0x9888, 0x14B10014 },
	{ 0x9888, 0x13837BE0 },
	{ 0x9888, 0x3B800060 },
	{ 0x9888, 0x3D800005 },
	{ 0x9888, 0x0A3F0023 },
	{ 0x9888, 0x103F0000 },
	{ 0x9888, 0x0A5A4000 },
	{ 0x9888, 0x0A1D4000 },
	{ 0x9888, 0x0E1F8000 },
	{ 0x9888, 0x0A391000 },
	{ 0x9888, 0x00DC4000 },
	{ 0x9888, 0x06DC8000 },
	{ 0x9888, 0x08DCC000 },
	{ 0x9888, 0x00BD8000 },
	{ 0x9888, 0x18BD0800 },
	{ 0x9888, 0x0ABF1180 },
	{ 0x9888, 0x10BF0000 },
	{ 0x9888, 0x00D84000 },
	{ 0x9888, 0x08D84000 },
	{ 0x9888, 0x0ADA8000 },
	{ 0x9888, 0x00DB4000 },
	{ 0x9888, 0x0EDB8000 },
	{ 0x9888, 0x18DB2400 },
	{ 0x9888, 0x0A9D8000 },
	{ 0x9888, 0x0C9F0800 },
	{ 0x9888, 0x0E9F2A00 },
	{ 0x9888, 0x109F0002 },
	{ 0x9888, 0x00B84000 },
	{ 0x9888, 0x0EB84000 },
	{ 0x9888, 0x16B84000 },
	{ 0x9888, 0x18B80001 },
	{ 0x9888, 0x00B92000 },
	{ 0x9888, 0x06B98000 },
	{ 0x9888, 0x08B9A000 },
	{ 0x9888, 0x0AB94000 },
	{ 0x9888, 0x00904000 },
	{ 0x9888, 0x08904000 },
	{ 0x9888, 0x00910030 },
	{ 0x9888, 0x08910031 },
	{ 0x9888, 0x10910000 },
	{ 0x9888, 0x00934000 },
	{ 0x9888, 0x16930020 },
	{ 0x9888, 0x06B08000 },
	{ 0x9888, 0x08B08000 },
	{ 0x9888, 0x06B11800 },
	{ 0x9888, 0x08B11880 },
	{ 0x9888, 0x10B10000 },
	{ 0x9888, 0x0EB34000 },
	{ 0x9888, 0x16B30080 },
	{ 0x9888, 0x01888000 },
	{ 0x9888, 0x0D88B800 },
	{ 0x9888, 0x1B8A0080 },
	{ 0x9888, 0x238B0040 },
	{ 0x9888, 0x258B26A0 },
	{ 0x9888, 0x018C4000 },
	{ 0x9888, 0x0F8C4000 },
	{ 0x9888, 0x178C2000 },
	{ 0x9888, 0x198C1100 },
	{ 0x9888, 0x018D2000 },
	{ 0x9888, 0x078D8000 },
	{ 0x9888, 0x098DA000 },
	{ 0x9888, 0x0B8D8000 },
	{ 0x9888, 0x1F85AA80 },
	{ 0x9888, 0x2185AAA0 },
	{ 0x9888, 0x2385002A },
	{ 0x9888, 0x0D831021 },
	{ 0x9888, 0x0F83572F },
	{ 0x9888, 0x01835680 },
	{ 0x9888, 0x038315AC },
	{ 0x9888, 0x0583002A },
	{ 0x9888, 0x11830000 },
	{ 0x9888, 0x19835400 },
	{ 0x9888, 0x1B830001 },
	{ 0x9888, 0x07830000 },
	{ 0x9888, 0x09830000 },
	{ 0x9888, 0x0184C000 },
	{ 0x9888, 0x07848000 },
	{ 0x9888, 0x0984C000 },
	{ 0x9888, 0x0B84C000 },
	{ 0x9888, 0x0D84C000 },
	{ 0x9888, 0x0F84C000 },
	{ 0x9888, 0x0384C000 },
	{ 0x9888, 0x05844000 },
	{ 0x9888, 0x1B80C137 },
	{ 0x9888, 0x1D80C147 },
	{ 0x9888, 0x21800000 },
	{ 0x9888, 0x1180C000 },
	{ 0x9888, 0x17808000 },
	{ 0x9888, 0x1980C000 },
	{ 0x9888, 0x1F80C000 },
	{ 0x9888, 0x1380C000 },
	{ 0x9888, 0x15804000 },
	{ 0x0D24, 0x00000000 },
	{ 0x9888, 0x4D805550 },
	{ 0x9888, 0x4F800335 },
	{ 0x9888, 0x43800802 },
	{ 0x9888, 0x51800400 },
	{ 0x9888, 0x458004A1 },
	{ 0x9888, 0x53805555 },
	{ 0x9888, 0x47800421 },
	{ 0x9888, 0x31800000 },
	{ 0x9888, 0x3F800421 },
	{ 0x9888, 0x41800841 },
	{ 0x9840, 0x00000080 },
};

static struct i915_oa_reg bdw_profile_3d_b_counter_config[] = {
	{ 0x2710, 0x00000000 },
	{ 0x2714, 0x00800000 },
	{ 0x2720, 0x00000000 },
	{ 0x2724, 0x00800000 },
};

static struct i915_oa_reg bdw_profile_3d_flex_counter_config[] = {
	{ 0xE458, 0x00005004 },
	{ 0xE558, 0x00010003 },
	{ 0xE658, 0x00012011 },
	{ 0xE758, 0x00015014 },
	{ 0xE45c, 0x00051050 },
	{ 0xE55c, 0x00053052 },
	{ 0xE65c, 0x00055054 },
};

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

static u32 gen7_forward_oa_snapshots(struct drm_i915_private *dev_priv,
				     u32 head,
				     u32 tail)
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
		/* The tail increases in 64 byte increments, not in
		 * format_size steps. */
		if (taken < snapshot_size)
			break;

		snapshot = oa_buf_base + (head & mask);
		head += snapshot_size;

		/* We currently only allow exclusive access to the counters
		 * so only have one event to forward too... */
		if (dev_priv->oa_pmu.event_active)
			forward_one_oa_snapshot_to_event(dev_priv, snapshot,
							 exclusive_event);
	}

	return dev_priv->oa_pmu.oa_buffer.gtt_offset + head;
}

static void gen7_flush_oa_snapshots(struct drm_i915_private *dev_priv,
				    bool skip_if_flushing)
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

	if (oastatus1 & (GEN7_OASTATUS1_OABUFFER_OVERFLOW |
			 GEN7_OASTATUS1_REPORT_LOST)) {

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
			 oastatus1 & GEN7_OASTATUS1_COUNTER_OVERFLOW ? 1 : 0,
			 oastatus1 & GEN7_OASTATUS1_OABUFFER_OVERFLOW ? 1 : 0,
			 oastatus1 & GEN7_OASTATUS1_REPORT_LOST ? 1 : 0);

		I915_WRITE(GEN7_OASTATUS1, oastatus1 &
			   ~(GEN7_OASTATUS1_OABUFFER_OVERFLOW |
			     GEN7_OASTATUS1_REPORT_LOST));
	}

	head = gen7_forward_oa_snapshots(dev_priv, head, tail);

	I915_WRITE(GEN7_OASTATUS2, (head & GEN7_OASTATUS2_HEAD_MASK) |
				    OA_MEM_SELECT_GGTT);

	spin_unlock_irqrestore(&dev_priv->oa_pmu.oa_buffer.flush_lock, flags);
}

static u32 gen8_forward_oa_snapshots(struct drm_i915_private *dev_priv,
				     u32 head,
				     u32 tail)
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
		u32 ctx_id;

		/* The tail increases in 64 byte increments, not in
		 * format_size steps. */
		if (taken < snapshot_size)
			break;

		/* All the report sizes factor neatly into the buffer
		 * size so we never expect to see a report split
		 * between the beginning and end of the buffer... */
		BUG_ON((OA_BUFFER_SIZE - (head & mask)) < snapshot_size);

		snapshot = oa_buf_base + (head & mask);

		//XXX: NB: don't mask lower 11 bits in execlist mode
		ctx_id = *(u32 *)(snapshot + 8) & 0xfffff800;

		if (dev_priv->oa_pmu.event_active) {
			u32 report_id = *(u32 *)snapshot;
			u32 reason = (report_id >> 19) & 0x3f;

			/* XXX: how should we handle this!? - need to find out when this can happen */
			if (!(report_id & (1<<25)))
				pr_err("report: context id invalid\n");

			if (reason & (1<<3))
				pr_err("context switch report: ctx_id=%x\n", ctx_id);

			if (dev_priv->oa_pmu.specific_ctx)
				pr_err("matching: specific_ctx_id=%x, current=%x\n", dev_priv->oa_pmu.specific_ctx_id, ctx_id);

			/* NB: For Gen 8 we handle per-context report filtering
			 * ourselves instead of programming the OA unit with a
			 * specific context id.
			 *
			 * NB: To allow userspace to calculate all counter
			 * deltas for a specific context we have to send the
			 * first report belonging to any subsequently
			 * switched-too context.
			 */
			if (!dev_priv->oa_pmu.specific_ctx ||
			    (dev_priv->oa_pmu.specific_ctx_id &&
			     ((dev_priv->oa_pmu.specific_ctx_id == ctx_id) ||
			      (dev_priv->oa_pmu.specific_ctx_id !=
			       dev_priv->oa_pmu.oa_buffer.last_ctx_id)))) {

				if (dev_priv->oa_pmu.specific_ctx &&
				    dev_priv->oa_pmu.specific_ctx_id != ctx_id &&
				    !(reason & (1<<3))) {
					pr_err("i915_oa: context switch seen, but not reported by OA\n");
				}

				forward_one_oa_snapshot_to_event(dev_priv,
								 snapshot,
								 exclusive_event);
			}
		}

		dev_priv->oa_pmu.oa_buffer.last_ctx_id = ctx_id;
		head += snapshot_size;
	}

	return dev_priv->oa_pmu.oa_buffer.gtt_offset + head;
}

static void gen8_flush_oa_snapshots(struct drm_i915_private *dev_priv,
				    bool skip_if_flushing)
{
	unsigned long flags;
	u32 oastatus;
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

	head = I915_READ(GEN8_OAHEADPTR);
	tail = I915_READ(GEN8_OATAILPTR);
	oastatus = I915_READ(GEN8_OASTATUS);

	if (oastatus & (GEN8_OASTATUS_OABUFFER_OVERFLOW |
			GEN8_OASTATUS_REPORT_LOST)) {

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
			 oastatus & GEN8_OASTATUS_COUNTER_OVERFLOW ? 1 : 0,
			 oastatus & GEN8_OASTATUS_OABUFFER_OVERFLOW ? 1 : 0,
			 oastatus & GEN8_OASTATUS_REPORT_LOST ? 1 : 0);

		I915_WRITE(GEN8_OASTATUS, oastatus &
			   ~(GEN8_OASTATUS_OABUFFER_OVERFLOW |
			     GEN8_OASTATUS_REPORT_LOST));
	}

	head = gen8_forward_oa_snapshots(dev_priv, head, tail);

	I915_WRITE(GEN8_OAHEADPTR, head);

	spin_unlock_irqrestore(&dev_priv->oa_pmu.oa_buffer.flush_lock, flags);
}

static void
oa_buffer_destroy(struct drm_i915_private *i915)
{
	mutex_lock(&i915->dev->struct_mutex);

	vunmap(i915->oa_pmu.oa_buffer.addr);
	i915_gem_object_ggtt_unpin(i915->oa_pmu.oa_buffer.obj);
	drm_gem_object_unreference(&i915->oa_pmu.oa_buffer.obj->base);

	i915->oa_pmu.oa_buffer.obj = NULL;
	i915->oa_pmu.oa_buffer.gtt_offset = 0;
	i915->oa_pmu.oa_buffer.addr = NULL;

	mutex_unlock(&i915->dev->struct_mutex);
}

static void i915_oa_event_destroy(struct perf_event *event)
{
	struct drm_i915_private *i915 =
		container_of(event->pmu, typeof(*i915), oa_pmu.pmu);

	WARN_ON(event->parent);

	oa_buffer_destroy(i915);

	i915->oa_pmu.specific_ctx = NULL;

	BUG_ON(i915->oa_pmu.exclusive_event != event);
	i915->oa_pmu.exclusive_event = NULL;

	intel_uncore_forcewake_put(i915, FORCEWAKE_ALL);
	intel_runtime_pm_put(i915);
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

	BUG_ON(!IS_HASWELL(dev_priv->dev) && !IS_BROADWELL(dev_priv->dev));
	BUG_ON(!mutex_is_locked(&dev_priv->dev->struct_mutex));
	BUG_ON(dev_priv->oa_pmu.oa_buffer.obj);

	spin_lock_init(&dev_priv->oa_pmu.oa_buffer.flush_lock);

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
	bo = i915_gem_alloc_object(dev_priv->dev, OA_BUFFER_SIZE + PAGE_SIZE);
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

	if (IS_HASWELL(dev_priv->dev)) {
		/* Pre-DevBDW: OABUFFER must be set with counters off,
		 * before OASTATUS1, but after OASTATUS2 */
		I915_WRITE(GEN7_OASTATUS2, dev_priv->oa_pmu.oa_buffer.gtt_offset |
			   OA_MEM_SELECT_GGTT); /* head */
		I915_WRITE(GEN7_OABUFFER, dev_priv->oa_pmu.oa_buffer.gtt_offset);
		I915_WRITE(GEN7_OASTATUS1, dev_priv->oa_pmu.oa_buffer.gtt_offset |
			   OABUFFER_SIZE_16M); /* tail */
	} else if (IS_BROADWELL(dev_priv->dev)) {
		I915_WRITE(GEN8_OAHEADPTR,
			   dev_priv->oa_pmu.oa_buffer.gtt_offset);
		/* PRM says:
		 *
		 *  "This MMIO must be set before the OATAILPTR
		 *  register and after the OAHEADPTR register. This is
		 *  to enable proper functionality of the overflow
		 *  bit."
		 */
		I915_WRITE(GEN8_OABUFFER, dev_priv->oa_pmu.oa_buffer.gtt_offset |
			   OABUFFER_SIZE_16M | OA_MEM_SELECT_GGTT);
		I915_WRITE(GEN8_OATAILPTR,
			   dev_priv->oa_pmu.oa_buffer.gtt_offset);
	}

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

	i915->oa_pmu.ops.flush_oa_snapshots(i915, true);

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
	struct drm_i915_private *dev_priv =
		container_of(event->pmu, typeof(*dev_priv), oa_pmu.pmu);
	u64 report_format;
	u64 profile;
	int ret = 0;

	if (event->attr.type != event->pmu->type) {
		pr_err("%s: spurious event type\n", __func__);
		return -ENOENT;
	}

        if (event->attr.config & ~(I915_PERF_OA_CTX_ID_MASK |
				   I915_PERF_OA_SINGLE_CONTEXT_ENABLE |
				   I915_PERF_OA_PROFILE_MASK |
				   I915_PERF_OA_FORMAT_MASK |
				   I915_PERF_OA_TIMER_EXPONENT_MASK)) {
		pr_err("%s: reserved config state non-zero\n", __func__);
		return -EINVAL;
	}

	/* To avoid the complexity of having to accurately filter
	 * counter snapshots and marshal to the appropriate client
	 * we currently only allow exclusive access */
	if (dev_priv->oa_pmu.oa_buffer.obj) {
		pr_err("%s: busy\n", __func__);
		return -EBUSY;
	}

        profile = event->attr.config & I915_PERF_OA_PROFILE_MASK;
        profile >>= I915_PERF_OA_PROFILE_SHIFT;
	dev_priv->oa_pmu.profile = profile;

	report_format = event->attr.config & I915_PERF_OA_FORMAT_MASK;
	report_format >>= I915_PERF_OA_FORMAT_SHIFT;
	dev_priv->oa_pmu.oa_buffer.format = report_format;

	if (IS_HASWELL(dev_priv->dev)) {
		int snapshot_size;

		if (profile > I915_PERF_OA_PROFILE_3D)
			return -EINVAL;

		if (report_format >= ARRAY_SIZE(hsw_perf_format_sizes))
			return -EINVAL;

		snapshot_size = hsw_perf_format_sizes[report_format];
		if (snapshot_size < 0)
			return -EINVAL;

		dev_priv->oa_pmu.oa_buffer.format_size = snapshot_size;
	} else if (IS_BROADWELL(dev_priv->dev)) {
		int snapshot_size;

		if (profile != I915_PERF_OA_PROFILE_3D) {
			pr_err("%s: non 3D profile\n", __func__);
			return -EINVAL;
		}

		if (report_format >= ARRAY_SIZE(bdw_perf_format_sizes)) {
			pr_err("%s: bad format\n", __func__);
			return -EINVAL;
		}

		snapshot_size = bdw_perf_format_sizes[report_format];
		if (snapshot_size < 0) {
			pr_err("%s: bad format\n", __func__);
			return -EINVAL;
		}

		dev_priv->oa_pmu.oa_buffer.format_size = snapshot_size;
	} else {
		BUG(); /* pmu shouldn't have been registered */
		return -ENODEV;
	}

	/* Since we are limited to an exponential scale for
	 * programming the OA sampling period we don't allow userspace
	 * to pass a precise attr.sample_period. */
	if (event->attr.freq ||
	    (event->attr.sample_period != 0 &&
	     event->attr.sample_period != 1)) {
		pr_err("%s: bad sample_period\n", __func__);
		return -EINVAL;
	}

	if (event->attr.sample_period) {
		u64 period_exponent = event->attr.config &
			I915_PERF_OA_TIMER_EXPONENT_MASK;

		period_exponent >>= I915_PERF_OA_TIMER_EXPONENT_SHIFT;
		dev_priv->oa_pmu.period_exponent = period_exponent;
	} else
		dev_priv->oa_pmu.period_exponent = 0;

	/* Instead of allowing userspace to configure the period via
	 * attr.sample_period we instead accept an exponent whereby
	 * the sample_period will be:
	 *
	 *   80ns * 2^(period_exponent + 1)
	 *
	 * Programming a period of 160 nanoseconds would not be very
	 * polite, so higher frequencies are reserved for root.
	 */
	if (dev_priv->oa_pmu.period_exponent < 15 && !CAP_SYS_ADMIN) {
		pr_err("%s: bad period exponent to low without root\n", __func__);
		return -EACCES;
	}

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
			if (!dev_priv->oa_pmu.specific_ctx)
				pr_err("%s: failed to lookup specific ctx\n", __func__);
		} else
			pr_err("%s: fdget for specific ctx failed\n", __func__);

		if (!dev_priv->oa_pmu.specific_ctx)
			return -EINVAL;
	}

	if (!dev_priv->oa_pmu.specific_ctx &&
	    i915_oa_event_paranoid && !capable(CAP_SYS_ADMIN)) {
		pr_err("%s: only root can profile cross-context\n", __func__);
		return -EACCES;
	}

	mutex_lock(&dev_priv->dev->struct_mutex);
	ret = init_oa_buffer(event);
	mutex_unlock(&dev_priv->dev->struct_mutex);

	if (ret) {
		pr_err("%s: init_oa_buffer failed\n", __func__);
		return ret;
	}

	BUG_ON(dev_priv->oa_pmu.exclusive_event);
	dev_priv->oa_pmu.exclusive_event = event;

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

static void gen7_update_oacontrol(struct drm_i915_private *dev_priv)
{
	BUG_ON(!spin_is_locked(&dev_priv->oa_pmu.lock));

	if (dev_priv->oa_pmu.event_active) {
		unsigned long ctx_id = dev_priv->oa_pmu.specific_ctx_id;

		if (dev_priv->oa_pmu.specific_ctx == NULL || ctx_id) {
			u64 period_exponent = dev_priv->oa_pmu.period_exponent;
			u64 report_format = dev_priv->oa_pmu.oa_buffer.format;

			I915_WRITE(GEN7_OACONTROL,
				   (ctx_id & GEN7_OACONTROL_CTX_MASK) |
				   (period_exponent <<
				    GEN7_OACONTROL_TIMER_PERIOD_SHIFT) |
				   (period_exponent ?
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
                          struct i915_oa_reg *regs,
                          int n_regs)
{
       int i;

       for (i = 0; i < n_regs; i++) {
               struct i915_oa_reg *reg = regs + i;

               I915_WRITE(reg->addr, reg->value);
       }
}

static void gen7_event_start(struct perf_event *event, int flags)
{
	struct drm_i915_private *dev_priv =
		container_of(event->pmu, typeof(*dev_priv), oa_pmu.pmu);
	u32 oastatus1, tail;

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

	I915_WRITE(GDT_CHICKEN_BITS, GT_NOA_ENABLE);

        if (dev_priv->oa_pmu.profile == I915_PERF_OA_PROFILE_3D) {
                config_oa_regs(dev_priv, hsw_profile_3d_mux_config,
                               ARRAY_SIZE(hsw_profile_3d_mux_config));
                config_oa_regs(dev_priv, hsw_profile_3d_b_counter_config,
                               ARRAY_SIZE(hsw_profile_3d_b_counter_config));
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

	gen7_update_oacontrol(dev_priv);

	/* Reset the head ptr to ensure we don't forward reports relating
	 * to a previous perf event */
	oastatus1 = I915_READ(GEN7_OASTATUS1);
	tail = oastatus1 & GEN7_OASTATUS1_TAIL_MASK;
	I915_WRITE(GEN7_OASTATUS2, (tail & GEN7_OASTATUS2_HEAD_MASK) |
				    OA_MEM_SELECT_GGTT);
}

static void gen8_event_start(struct perf_event *event, int flags)
{
	struct drm_i915_private *dev_priv =
		container_of(event->pmu, typeof(*dev_priv), oa_pmu.pmu);
	u64 report_format = dev_priv->oa_pmu.oa_buffer.format;
	u32 tail;

	pr_err("%s\n", __func__);

#warning "check if this is needed on BDW..."
	I915_WRITE(GDT_CHICKEN_BITS, GT_NOA_ENABLE);

        if (dev_priv->oa_pmu.profile == I915_PERF_OA_PROFILE_3D) {
		if (INTEL_INFO(dev_priv)->slice_mask & 0x1) {
			int n = ARRAY_SIZE(bdw_profile_3d_noa_slice0_mux_config);
			config_oa_regs(dev_priv,
					bdw_profile_3d_noa_slice0_mux_config, n);
		}
		if (INTEL_INFO(dev_priv)->slice_mask & 0x2) {
			int n = ARRAY_SIZE(bdw_profile_3d_noa_slice1_mux_config);
			config_oa_regs(dev_priv,
					bdw_profile_3d_noa_slice1_mux_config, n);
		}

                config_oa_regs(dev_priv, bdw_profile_3d_b_counter_config,
                               ARRAY_SIZE(bdw_profile_3d_b_counter_config));
                config_oa_regs(dev_priv, bdw_profile_3d_flex_counter_config,
                               ARRAY_SIZE(bdw_profile_3d_flex_counter_config));
	} else {
		BUG(); /* should have been validated in _init */
	}

	if (dev_priv->oa_pmu.specific_ctx) {
		struct intel_context *ctx = dev_priv->oa_pmu.specific_ctx;
		struct drm_i915_gem_object *obj = ctx->legacy_hw_ctx.rcs_state;

		if (i915_gem_obj_is_pinned(obj)) {
			dev_priv->oa_pmu.specific_ctx_id =
				i915_gem_obj_ggtt_offset(obj);
			pr_err("i915_oa: specific_ctx_id=%x\n", dev_priv->oa_pmu.specific_ctx_id);
		} else
		    pr_err("%s: specific context not currently pinned\n", __func__);
	}

	/* XXX: Although BDW supports explicitly specifying a
	 * context-id to only report per-context metrics we
	 * instead rely on the context-id field of reports for
	 * filtering instead.
	 */
	I915_WRITE(GEN8_OACONTROL, (report_format <<
				    GEN8_OA_REPORT_FORMAT_SHIFT) |
				   GEN8_OA_COUNTER_ENABLE);

	/* XXX: See the note in i915_oa_context_switch_notify
	 * about programming GEN8_OACTXCONTROL. */
	I915_WRITE(GEN8_OACTXCONTROL, (dev_priv->oa_pmu.period_exponent <<
				       GEN8_OA_TIMER_PERIOD_SHIFT) |
				      (dev_priv->oa_pmu.period_exponent ?
				       GEN8_OA_TIMER_ENABLE : 0) |
				      GEN8_OA_COUNTER_RESUME);

	/* Reset the head ptr to ensure we don't forward reports relating
	 * to a previous perf event */
	tail = I915_READ(GEN8_OATAILPTR);
	I915_WRITE(GEN8_OAHEADPTR, tail);
}

static void i915_oa_event_start(struct perf_event *event, int flags)
{
	struct drm_i915_private *dev_priv =
		container_of(event->pmu, typeof(*dev_priv), oa_pmu.pmu);
	unsigned long lock_flags;

	spin_lock_irqsave(&dev_priv->oa_pmu.lock, lock_flags);

	dev_priv->oa_pmu.event_active = true;
	dev_priv->oa_pmu.ops.event_start(event, flags);

	spin_unlock_irqrestore(&dev_priv->oa_pmu.lock, lock_flags);

	if (event->attr.sample_period)
		__hrtimer_start_range_ns(&dev_priv->oa_pmu.timer,
					 ns_to_ktime(PERIOD), 0,
					 HRTIMER_MODE_REL_PINNED, 0);

	event->hw.state = 0;
}

static void gen7_event_stop(struct perf_event *event, int flags)
{
	struct drm_i915_private *dev_priv =
		container_of(event->pmu, typeof(*dev_priv), oa_pmu.pmu);

	I915_WRITE(GEN7_OACONTROL, 0);
}

static void gen8_event_stop(struct perf_event *event, int flags)
{
	struct drm_i915_private *dev_priv =
		container_of(event->pmu, typeof(*dev_priv), oa_pmu.pmu);

	I915_WRITE(GEN8_OACONTROL, 0);
}

static void i915_oa_event_stop(struct perf_event *event, int flags)
{
	struct drm_i915_private *dev_priv =
		container_of(event->pmu, typeof(*dev_priv), oa_pmu.pmu);
	unsigned long lock_flags;

	spin_lock_irqsave(&dev_priv->oa_pmu.lock, lock_flags);
	dev_priv->oa_pmu.event_active = false;

	dev_priv->oa_pmu.ops.event_stop(event, flags);

	spin_unlock_irqrestore(&dev_priv->oa_pmu.lock, lock_flags);

	if (event->attr.sample_period) {
		hrtimer_cancel(&dev_priv->oa_pmu.timer);
		dev_priv->oa_pmu.ops.flush_oa_snapshots(dev_priv, false);
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

static void i915_oa_event_flush(struct perf_event *event)
{
	struct drm_i915_private *i915 =
		container_of(event->pmu, typeof(*i915), oa_pmu.pmu);

	/* We want userspace to be able to use a read() to explicitly
	 * flush OA counter snapshots... */
	if (event->attr.sample_period)
		i915->oa_pmu.ops.flush_oa_snapshots(i915, true);
}

static int i915_oa_event_event_idx(struct perf_event *event)
{
	return 0;
}

static void gen7_context_pin_notify(struct drm_i915_private *dev_priv,
				    struct intel_context *context)
{
	if (dev_priv->oa_pmu.specific_ctx == context)
		gen7_update_oacontrol(dev_priv);
}

void i915_oa_context_pin_notify(struct drm_i915_private *dev_priv,
				struct intel_context *context)
{
	unsigned long flags;

	if (dev_priv->oa_pmu.pmu.event_init == NULL)
		return;

	spin_lock_irqsave(&dev_priv->oa_pmu.lock, flags);

	if (dev_priv->oa_pmu.specific_ctx == context) {
		struct intel_context *ctx = dev_priv->oa_pmu.specific_ctx;
		struct drm_i915_gem_object *obj = ctx->legacy_hw_ctx.rcs_state;

		dev_priv->oa_pmu.specific_ctx_id =
			i915_gem_obj_ggtt_offset(obj);
#warning "if a specific ctx is pinned with a new address, we may need to flush the oabuffer in case it refers to the old id"
		//pr_err("%s: specific_ctx_id=%x\n", __func__, dev_priv->oa_pmu.specific_ctx_id);
	}

	if (dev_priv->oa_pmu.ops.context_pin_notify)
		dev_priv->oa_pmu.ops.context_pin_notify(dev_priv, context);

	spin_unlock_irqrestore(&dev_priv->oa_pmu.lock, flags);
}

static void gen7_context_unpin_notify(struct drm_i915_private *dev_priv,
				      struct intel_context *context)
{
	if (dev_priv->oa_pmu.specific_ctx == context)
		gen7_update_oacontrol(dev_priv);
}

void i915_oa_context_unpin_notify(struct drm_i915_private *dev_priv,
				  struct intel_context *context)
{
	unsigned long flags;

	if (dev_priv->oa_pmu.pmu.event_init == NULL)
		return;

	spin_lock_irqsave(&dev_priv->oa_pmu.lock, flags);

	if (dev_priv->oa_pmu.specific_ctx == context) {
		//pr_err("%s: specific_ctx_id=%x\n", __func__, dev_priv->oa_pmu.specific_ctx_id);
		dev_priv->oa_pmu.specific_ctx_id = 0;
	}

	if (dev_priv->oa_pmu.ops.context_unpin_notify)
		dev_priv->oa_pmu.ops.context_unpin_notify(dev_priv, context);

	spin_unlock_irqrestore(&dev_priv->oa_pmu.lock, flags);
}

static void gen8_context_switch_notify(struct drm_i915_private *dev_priv,
				       struct intel_engine_cs *ring)
{
	struct perf_event *event = dev_priv->oa_pmu.exclusive_event;
	int n_flex_regs = ARRAY_SIZE(bdw_profile_3d_flex_counter_config);
	struct i915_oa_reg *flex_regs = bdw_profile_3d_flex_counter_config;
	int ret;
	int i;

	ret = intel_ring_begin(ring, n_flex_regs * 2 + 4);
	if (ret)
		return;

	/* XXX: On BDW the exponent for periodic counter
	 * sampling is maintained as per-context state which
	 * is a bit awkward considering that we often want
	 * to use periodic sampling for collecting
	 * cross-context metrics.
	 *
	 * At the point that userspace enables an event with
	 * a given timer period we need to consider that:
	 *
	 * - There could already be a context running whose
	 *   state can be updated immediately via mmio.
	 * - We should beware that when the HW next switches
	 *   to another context it will automatically load an
	 *   out-of-date OA configuration from its register
	 *   state context.
	 *
	 * Since there isn't currently much precedent for
	 * directly fiddling with the register state contexts
	 * that the hardware re-loads registers from we are
	 * currently relying on LRIs to setup the OA state
	 * when switching context but it should be noted that
	 * there is a race between the HW acting on the state
	 * that's automatically re-loaded and the LRIs being
	 * executed.
	 */

	intel_ring_emit(ring, MI_LOAD_REGISTER_IMM(n_flex_regs + 1));

	intel_ring_emit(ring, GEN8_OACTXCONTROL);
	intel_ring_emit(ring,
			(dev_priv->oa_pmu.period_exponent <<
			 GEN8_OA_TIMER_PERIOD_SHIFT) |
			(event->attr.sample_period ?
			 GEN8_OA_TIMER_ENABLE : 0) |
			GEN8_OA_COUNTER_RESUME);

	for (i = 0; i < n_flex_regs; i++) {
		intel_ring_emit(ring, flex_regs[i].addr);
		intel_ring_emit(ring, flex_regs[i].value);
	}
	intel_ring_emit(ring, MI_NOOP);
	intel_ring_advance(ring);
}

void i915_oa_context_switch_notify(struct drm_i915_private *dev_priv,
				   struct intel_engine_cs *ring)
{
	if (dev_priv->oa_pmu.pmu.event_init == NULL ||
	    !dev_priv->oa_pmu.event_active)
		return;

	if (dev_priv->oa_pmu.ops.context_switch_notify)
		dev_priv->oa_pmu.ops.context_switch_notify(dev_priv, ring);
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

	if (!(IS_HASWELL(dev) || IS_BROADWELL(dev)))
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

	spin_lock_init(&i915->oa_pmu.lock);

	i915->oa_pmu.pmu.capabilities  = PERF_PMU_CAP_IS_DEVICE;

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

	if (IS_HASWELL(dev)) {
		i915->oa_pmu.ops.flush_oa_snapshots = gen7_flush_oa_snapshots;
		i915->oa_pmu.ops.event_start = gen7_event_start;
		i915->oa_pmu.ops.event_stop = gen7_event_stop;
		i915->oa_pmu.ops.context_pin_notify = gen7_context_pin_notify;
		i915->oa_pmu.ops.context_unpin_notify = gen7_context_unpin_notify;
	} else {
		i915->oa_pmu.ops.flush_oa_snapshots = gen8_flush_oa_snapshots;
		i915->oa_pmu.ops.event_start = gen8_event_start;
		i915->oa_pmu.ops.event_stop = gen8_event_stop;
		i915->oa_pmu.ops.context_switch_notify = gen8_context_switch_notify;
	}

	if (perf_pmu_register(&i915->oa_pmu.pmu, "i915_oa", -1))
		i915->oa_pmu.pmu.event_init = NULL;
}

void i915_oa_pmu_unregister(struct drm_device *dev)
{
	struct drm_i915_private *i915 = to_i915(dev);

	if (i915->oa_pmu.pmu.event_init == NULL)
		return;

	unregister_sysctl_table(i915->oa_pmu.sysctl_header);

	perf_pmu_unregister(&i915->oa_pmu.pmu);
	i915->oa_pmu.pmu.event_init = NULL;
}
