#include <linux/perf_event.h>
#include <linux/sizes.h>

#include "i915_drv.h"
#include "intel_ringbuffer.h"

static enum hrtimer_restart i915_ring_event_hrtimer(struct hrtimer *hrtimer)
{
	struct drm_i915_private *dev_priv;
	enum hrtimer_restart ret = HRTIMER_RESTART;
	struct perf_sample_data data;
	struct pt_regs *regs;
	struct perf_event *event;
	u64 period;

	event = container_of(hrtimer, struct perf_event, hw.hrtimer);

	if (event->state != PERF_EVENT_STATE_ACTIVE)
		return HRTIMER_NORESTART;

	event->pmu->read(event);

	perf_sample_data_init(&data, 0, event->hw.last_period);

	dev_priv = container_of(event->pmu, typeof(*dev_priv), pmu);

	if (perf_event_overflow(event, &data, &dev_priv->dummy_regs))
	    ret = HRTIMER_NORESTART;

	period = max_t(u64, 10000, event->hw.sample_period);
	hrtimer_forward_now(hrtimer, ns_to_ktime(period));

	return ret;
}

static void perf_ring_event_start_hrtimer(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	s64 period;

	if (!is_sampling_event(event))
		return;

	period = local64_read(&hwc->period_left);
	if (period) {
		if (period < 0)
			period = 10000;

		local64_set(&hwc->period_left, 0);
	} else {
		period = max_t(u64, 10000, hwc->sample_period);
	}
	__hrtimer_start_range_ns(&hwc->hrtimer,
				ns_to_ktime(period), 0,
				HRTIMER_MODE_REL_PINNED, 0);
}

static void i915_ring_event_cancel_hrtimer(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;

	if (is_sampling_event(event)) {
		ktime_t remaining = hrtimer_get_remaining(&hwc->hrtimer);
		local64_set(&hwc->period_left, ktime_to_ns(remaining));

		hrtimer_cancel(&hwc->hrtimer);
	}
}

static void i915_ring_event_init_hrtimer(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;

	if (!is_sampling_event(event))
		return;

	hrtimer_init(&hwc->hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	hwc->hrtimer.function = perf_swevent_hrtimer;

	/*
	 * Since hrtimers have a fixed rate, we can do a static freq->period
	 * mapping and avoid the whole period adjust feedback stuff.
	 */
	if (event->attr.freq) {
		long freq = event->attr.sample_freq;

		event->attr.sample_period = NSEC_PER_SEC / freq;
		hwc->sample_period = event->attr.sample_period;
		local64_set(&hwc->period_left, hwc->sample_period);
		hwc->last_period = hwc->sample_period;
		event->attr.freq = 0;
	}
}

static void i915_ring_event_destroy(struct perf_event *event)
{
	struct drm_i915_private *i915 =
		container_of(event->pmu, typeof(*i915), pmu);

	WARN_ON(event->parent);
}

static int i915_ring_event_init(struct perf_event *event)
{
	struct perf_event_context *ctx = event->ctx;
	struct drm_i915_private *i915 =
		container_of(event->pmu, typeof(*i915), pmu);

	if (event->attr.type != event->pmu->type)
		return -ENOENT;

	/* Using PERF_PMU_CAP_IS_DEVICE means we are responsible for
	 * performing our own permissions checks... */
	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;

	/* When tracing a specific pid events/core will enable/disable
	 * the event only while that pid is running on a cpu but that
	 * doesn't really make sense here. */
	if (ctx->task)
		return -EINVAL;

	/* On Haswell, concurrent mmio access to the same cache line
	 * can cause a lock up so a simple way to avoid that is to
	 * only allow exclusive access... */
	if (IS_HASWELL(i915->dev) && i915->have_perf_client)
		return -EBUSY;

	/* unsupported modes and filters */
        if (event->attr.exclude_user   ||
	    event->attr.exclude_kernel ||
            event->attr.exclude_hv     ||
            event->attr.exclude_idle   ||
            event->attr.exclude_host   ||
            event->attr.exclude_guest)
                return -EINVAL;

	if (has_branch_stack(event))
		return -EOPNOTSUPP;

	event->destroy = i915_ring_event_destroy;

	return 0;
}

static void i915_ring_event_start(struct perf_event *event, int flags)
{
	struct drm_i915_private *dev_priv =
		container_of(event->pmu, typeof(*dev_priv), pmu);

	if (event->attr.sample_period) {
		__hrtimer_start_range_ns(&dev_priv->ring_pmu_timer,
					 ns_to_ktime(PERIOD), 0,
					 HRTIMER_MODE_REL_PINNED, 0);
	}

	event->hw.state = 0;
}

static void i915_ring_event_stop(struct perf_event *event, int flags)
{
	struct drm_i915_private *dev_priv =
		container_of(event->pmu, typeof(*dev_priv), pmu);

	if (event->attr.sample_period)
		hrtimer_cancel(&dev_priv->ring_pmu_timer);

	event->hw.state = PERF_HES_STOPPED;
}


static int i915_ring_event_add(struct perf_event *event, int flags)
{
	struct drm_i915_private *dev_priv =
		container_of(event->pmu, typeof(*dev_priv), pmu);
	struct hw_perf_event *hwc = &event->hw;

	if (flags & PERF_EF_START)
		i915_ring_event_start(event, flags);

	return 0;
}

static void i915_ring_event_del(struct perf_event *event, int flags)
{
	struct drm_i915_private *dev_priv =
		container_of(event->pmu, typeof(*dev_priv), pmu);

	i915_ring_event_stop(event, flags);
}

static void i915_ring_event_read(struct perf_event *event)
{
	struct drm_i915_private *i915 =
		container_of(event->pmu, typeof(*i915), pmu);

	/* XXX: what counter should we report here? */
	local64_set(&event->count, 0);
}

static int i915_ring_event_event_idx(struct perf_event *event)
{
	return 0;
}

void i915_ring_pmu_register(struct drm_device *dev)
{
	struct drm_i915_private *i915 = to_i915(dev);

	/* It doesn't really make sense to forward any details about
	 * the state of the cpu with samples for this pmu. */
	i915->dummy_regs = *task_pt_regs(current);

	i915->ring_pmu.capabilities  = PERF_PMU_CAP_IS_DEVICE;
	i915->ring_pmu.task_ctx_nr   = perf_invalid_context;
	i915->ring_pmu.event_init    = i915_ring_event_init;
	i915->ring_pmu.add	     = i915_ring_event_add;
	i915->ring_pmu.del	     = i915_ring_event_del;
	i915->ring_pmu.start	     = i915_ring_event_start;
	i915->ring_pmu.stop	     = i915_ring_event_stop;
	i915->ring_pmu.read	     = i915_ring_event_read;
	i915->ring_pmu.event_idx     = i915_ring_event_event_idx;

	if (perf_pmu_register(&i915->ring_pmu, "i915_ring", -1))
		i915->ring_pmu.event_init = NULL;
}

void i915_ring_pmu_unregister(struct drm_device *dev)
{
	struct drm_i915_private *i915 = to_i915(dev);

	if (i915->ring_pmu.event_init == NULL)
		return;

	perf_pmu_unregister(&i915->ring_pmu);
	i915->ring_pmu.event_init = NULL;
}
