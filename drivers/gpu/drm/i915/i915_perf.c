/*
 * Copyright © 2015-2016 Intel Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * Authors:
 *   Robert Bragg <robert@sixbynine.org>
 */


/**
 * DOC: i915 Perf Overview
 *
 * Gen graphics supports a large number of performance counters that can help
 * driver and application developers understand and optimize their use of the
 * GPU.
 *
 * This i915 perf interface enables userspace to configure and open a file
 * descriptor representing a stream of GPU metrics which can then be read() as
 * a stream of sample records.
 *
 * The interface is particularly suited to exposing buffered metrics that are
 * captured by DMA from the GPU, unsynchronized with and unrelated to the CPU.
 *
 * Streams representing a single context are accessible to applications with a
 * corresponding drm file descriptor, such that OpenGL can use the interface
 * without special privileges. Access to system-wide metrics requires root
 * privileges by default, unless changed via the dev.i915.perf_event_paranoid
 * sysctl option.
 *
 */

/**
 * DOC: i915 Perf History and Comparison with Core Perf
 *
 * The interface was initially inspired by the core Perf infrastructure but
 * some notable differences are:
 *
 * i915 perf file descriptors represent a "stream" instead of an "event"; where
 * a perf event primarily corresponds to a single 64bit value, while a stream
 * might sample sets of tightly-coupled counters, depending on the
 * configuration.  For example the Gen OA unit isn't designed to support
 * orthogonal configurations of individual counters; it's configured for a set
 * of related counters. Samples for an i915 perf stream capturing OA metrics
 * will include a set of counter values packed in a compact HW specific format.
 * The OA unit supports a number of different packing formats which can be
 * selected by the user opening the stream. Perf has support for grouping
 * events, but each event in the group is configured, validated and
 * authenticated individually with separate system calls.
 *
 * i915 perf stream configurations are provided as an array of u64 (key,value)
 * pairs, instead of a fixed struct with multiple miscellaneous config members,
 * interleaved with event-type specific members.
 *
 * i915 perf doesn't support exposing metrics via an mmap'd circular buffer.
 * The supported metrics are being written to memory by the GPU unsynchronized
 * with the CPU, using HW specific packing formats for counter sets. Sometimes
 * the constraints on HW configuration require reports to be filtered before it
 * would be acceptable to expose them to unprivileged applications - to hide
 * the metrics of other processes/contexts. For these use cases a read() based
 * interface is a good fit, and provides an opportunity to filter data as it
 * gets copied from the GPU mapped buffers to userspace buffers.
 *
 *
 * Issues hit with first prototype based on Core Perf
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * The first prototype of this driver was based on the core perf
 * infrastructure, and while we did make that mostly work, with some changes to
 * perf, we found we were breaking or working around too many assumptions baked
 * into perf's currently cpu centric design.
 *
 * In the end we didn't see a clear benefit to making perf's implementation and
 * interface more complex by changing design assumptions while we knew we still
 * wouldn't be able to use any existing perf based userspace tools.
 *
 * Also considering the Gen specific nature of the Observability hardware and
 * how userspace will sometimes need to combine i915 perf OA metrics with
 * side-band OA data captured via MI_REPORT_PERF_COUNT commands; we're
 * expecting the interface to be used by a platform specific userspace such as
 * OpenGL or tools. This is to say; we aren't inherently missing out on having
 * a standard vendor/architecture agnostic interface by not using perf.
 *
 *
 * For posterity, in case we might re-visit trying to adapt core perf to be
 * better suited to exposing i915 metrics these were the main pain points we
 * hit:
 *
 * - The perf based OA PMU driver broke some significant design assumptions:
 *
 *   Existing perf pmus are used for profiling work on a cpu and we were
 *   introducing the idea of _IS_DEVICE pmus with different security
 *   implications, the need to fake cpu-related data (such as user/kernel
 *   registers) to fit with perf's current design, and adding _DEVICE records
 *   as a way to forward device-specific status records.
 *
 *   The OA unit writes reports of counters into a circular buffer, without
 *   involvement from the CPU, making our PMU driver the first of a kind.
 *
 *   Given the way we were periodically forward data from the GPU-mapped, OA
 *   buffer to perf's buffer, those bursts of sample writes looked to perf like
 *   we were sampling too fast and so we had to subvert its throttling checks.
 *
 *   Perf supports groups of counters and allows those to be read via
 *   transactions internally but transactions currently seem designed to be
 *   explicitly initiated from the cpu (say in response to a userspace read())
 *   and while we could pull a report out of the OA buffer we can't
 *   trigger a report from the cpu on demand.
 *
 *   Related to being report based; the OA counters are configured in HW as a
 *   set while perf generally expects counter configurations to be orthogonal.
 *   Although counters can be associated with a group leader as they are
 *   opened, there's no clear precedent for being able to provide group-wide
 *   configuration attributes (for example we want to let userspace choose the
 *   OA unit report format used to capture all counters in a set, or specify a
 *   GPU context to filter metrics on). We avoided using perf's grouping
 *   feature and forwarded OA reports to userspace via perf's 'raw' sample
 *   field. This suited our userspace well considering how coupled the counters
 *   are when dealing with normalizing. It would be inconvenient to split
 *   counters up into separate events, only to require userspace to recombine
 *   them. For Mesa it's also convenient to be forwarded raw, periodic reports
 *   for combining with the side-band raw reports it captures using
 *   MI_REPORT_PERF_COUNT commands.
 *
 *   - As a side note on perf's grouping feature; there was also some concern
 *     that using PERF_FORMAT_GROUP as a way to pack together counter values
 *     would quite drastically inflate our sample sizes, which would likely
 *     lower the effective sampling resolutions we could use when the available
 *     memory bandwidth is limited.
 *
 *     With the OA unit's report formats, counters are packed together as 32
 *     or 40bit values, with the largest report size being 256 bytes.
 *
 *     PERF_FORMAT_GROUP values are 64bit, but there doesn't appear to be a
 *     documented ordering to the values, implying PERF_FORMAT_ID must also be
 *     used to add a 64bit ID before each value; giving 16 bytes per counter.
 *
 *   Related to counter orthogonality; we can't time share the OA unit, while
 *   event scheduling is a central design idea within perf for allowing
 *   userspace to open + enable more events than can be configured in HW at any
 *   one time.  The OA unit is not designed to allow re-configuration while in
 *   use. We can't reconfigure the OA unit without losing internal OA unit
 *   state which we can't access explicitly to save and restore. Reconfiguring
 *   the OA unit is also relatively slow, involving ~100 register writes. From
 *   userspace Mesa also depends on a stable OA configuration when emitting
 *   MI_REPORT_PERF_COUNT commands and importantly the OA unit can't be
 *   disabled while there are outstanding MI_RPC commands lest we hang the
 *   command streamer.
 *
 *   The contents of sample records aren't extensible by device drivers (i.e.
 *   the sample_type bits). As an example; Sourab Gupta had been looking to
 *   attach GPU timestamps to our OA samples. We were shoehorning OA reports
 *   into sample records by using the 'raw' field, but it's tricky to pack more
 *   than one thing into this field because events/core.c currently only lets a
 *   pmu give a single raw data pointer plus len which will be copied into the
 *   ring buffer. To include more than the OA report we'd have to copy the
 *   report into an intermediate larger buffer. I'd been considering allowing a
 *   vector of data+len values to be specified for copying the raw data, but
 *   it felt like a kludge to being using the raw field for this purpose.
 *
 * - It felt like our perf based PMU was making some technical compromises
 *   just for the sake of using perf:
 *
 *   perf_event_open() requires events to either relate to a pid or a specific
 *   cpu core, while our device pmu related to neither.  Events opened with a
 *   pid will be automatically enabled/disabled according to the scheduling of
 *   that process - so not appropriate for us. When an event is related to a
 *   cpu id, perf ensures pmu methods will be invoked via an inter process
 *   interrupt on that core. To avoid invasive changes our userspace opened OA
 *   perf events for a specific cpu. This was workable but it meant the
 *   majority of the OA driver ran in atomic context, including all OA report
 *   forwarding, which wasn't really necessary in our case and seems to make
 *   our locking requirements somewhat complex as we handled the interaction
 *   with the rest of the i915 driver.
 */

#include <linux/anon_inodes.h>
#include <linux/sizes.h>

#include "i915_drv.h"
#include "i915_oa_hsw.h"
#include "i915_oa_bdw.h"
#include "i915_oa_chv.h"
#include "i915_oa_sklgt2.h"
#include "i915_oa_sklgt3.h"
#include "i915_oa_sklgt4.h"
#include "i915_oa_bxt.h"

/* HW requires this to be a power of two, between 128k and 16M, though driver
 * is currently generally designed assuming the largest 16M size is used such
 * that the overflow cases are unlikely in normal operation.
 */
#define OA_BUFFER_SIZE		SZ_16M

#define OA_TAKEN(tail, head)	((tail - head) & (OA_BUFFER_SIZE - 1))

/**
 * DOC: OA Tail Pointer Race
 *
 * There's a HW race condition between OA unit tail pointer register updates and
 * writes to memory whereby the tail pointer can sometimes get ahead of what's
 * been written out to the OA buffer so far (in terms of what's visible to the
 * CPU).
 *
 * Although this can be observed explicitly while copying reports to userspace
 * by checking for a zeroed report-id field in tail reports, we want to account
 * for this earlier, as part of the _oa_buffer_check to avoid lots of redundant
 * read() attempts.
 *
 * In effect we define a tail pointer for reading that lags the real tail
 * pointer by at least %OA_TAIL_MARGIN_NSEC nanoseconds, which gives enough
 * time for the corresponding reports to become visible to the CPU.
 *
 * To manage this we actually track two tail pointers:
 *  1) An 'aging' tail with an associated timestamp that is tracked until we
 *     can trust the corresponding data is visible to the CPU; at which point
 *     it is considered 'aged'.
 *  2) An 'aged' tail that can be used for read()ing.
 *
 * The two separate pointers let us decouple read()s from tail pointer aging.
 *
 * The tail pointers are checked and updated at a limited rate within a hrtimer
 * callback (the same callback that is used for delivering POLLIN events)
 *
 * Initially the tails are marked invalid with %INVALID_TAIL_PTR which
 * indicates that an updated tail pointer is needed.
 *
 * Most of the implementation details for this workaround are in
 * gen7_oa_buffer_check_unlocked() and gen7_appand_oa_reports()
 *
 * Note for posterity: previously the driver used to define an effective tail
 * pointer that lagged the real pointer by a 'tail margin' measured in bytes
 * derived from %OA_TAIL_MARGIN_NSEC and the configured sampling frequency.
 * This was flawed considering that the OA unit may also automatically generate
 * non-periodic reports (such as on context switch) or the OA unit may be
 * enabled without any periodic sampling.
 */
#define OA_TAIL_MARGIN_NSEC	100000ULL
#define INVALID_TAIL_PTR	0xffffffff

/* frequency for checking whether the OA unit has written new reports to the
 * circular OA buffer...
 */
#define POLL_FREQUENCY 200
#define POLL_PERIOD (NSEC_PER_SEC / POLL_FREQUENCY)

/* for sysctl proc_dointvec_minmax of dev.i915.perf_stream_paranoid */
static int zero;
static int one = 1;
static u32 i915_perf_stream_paranoid = true;

/* The maximum exponent the hardware accepts is 63 (essentially it selects one
 * of the 64bit timestamp bits to trigger reports from) but there's currently
 * no known use case for sampling as infrequently as once per 47 thousand years.
 *
 * Since the timestamps included in OA reports are only 32bits it seems
 * reasonable to limit the OA exponent where it's still possible to account for
 * overflow in OA report timestamps.
 */
#define OA_EXPONENT_MAX 31

#define INVALID_CTX_ID 0xffffffff

/* On Gen8+ automatically triggered OA reports include a 'reason' field... */
#define OAREPORT_REASON_MASK           0x3f
#define OAREPORT_REASON_SHIFT          19
#define OAREPORT_REASON_TIMER          (1<<0)
#define OAREPORT_REASON_CTX_SWITCH     (1<<3)
#define OAREPORT_REASON_CLK_RATIO      (1<<5)

#define OA_ADDR_ALIGN 64
#define TS_ADDR_ALIGN 8
#define I915_PERF_TS_SAMPLE_SIZE 8

/*Data common to perf samples (periodic OA / CS based OA / Timestamps)*/
struct sample_data {
	u32 source;
	u32 ctx_id;
	u32 pid;
	u32 tag;
	u64 ts;
	const u8 *report;
};

/* For sysctl proc_dointvec_minmax of i915_oa_max_sample_rate
 *
 * 160ns is the smallest sampling period we can theoretically program the OA
 * unit with on Haswell, corresponding to 6.25MHz.
 */
static int oa_sample_rate_hard_limit = 6250000;

/* Theoretically we can program the OA unit to sample every 160ns but don't
 * allow that by default unless root...
 *
 * The default threshold of 100000Hz is based on perf's similar
 * kernel.perf_event_max_sample_rate sysctl parameter.
 */
static u32 i915_oa_max_sample_rate = 100000;

/* XXX: beware if future OA HW adds new report formats that the current
 * code assumes all reports have a power-of-two size and ~(size - 1) can
 * be used as a mask to align the OA tail pointer.
 */
static struct i915_oa_format hsw_oa_formats[I915_OA_FORMAT_MAX] = {
	[I915_OA_FORMAT_A13]	    = { 0, 64 },
	[I915_OA_FORMAT_A29]	    = { 1, 128 },
	[I915_OA_FORMAT_A13_B8_C8]  = { 2, 128 },
	/* A29_B8_C8 Disallowed as 192 bytes doesn't factor into buffer size */
	[I915_OA_FORMAT_B4_C8]	    = { 4, 64 },
	[I915_OA_FORMAT_A45_B8_C8]  = { 5, 256 },
	[I915_OA_FORMAT_B4_C8_A16]  = { 6, 128 },
	[I915_OA_FORMAT_C4_B8]	    = { 7, 64 },
};

static struct i915_oa_format gen8_plus_oa_formats[I915_OA_FORMAT_MAX] = {
	[I915_OA_FORMAT_A12]		    = { 0, 64 },
	[I915_OA_FORMAT_A12_B8_C8]	    = { 2, 128 },
	[I915_OA_FORMAT_A32u40_A4u32_B8_C8] = { 5, 256 },
	[I915_OA_FORMAT_C4_B8]		    = { 7, 64 },
};

/* Duplicated from similar static enum in i915_gem_execbuffer.c */
#define I915_USER_RINGS (4)
static const enum intel_engine_id user_ring_map[I915_USER_RINGS + 1] = {
	[I915_EXEC_DEFAULT]	= RCS,
	[I915_EXEC_RENDER]	= RCS,
	[I915_EXEC_BLT]		= BCS,
	[I915_EXEC_BSD]		= VCS,
	[I915_EXEC_VEBOX]	= VECS
};

#define SAMPLE_OA_REPORT      (1<<0)
#define SAMPLE_OA_SOURCE_INFO	(1<<1)
#define SAMPLE_CTX_ID		(1<<2)
#define SAMPLE_PID		(1<<3)
#define SAMPLE_TAG		(1<<4)
#define SAMPLE_TS		(1<<5)

/**
 * struct perf_open_properties - for validated properties given to open a stream
 * @sample_flags: `DRM_I915_PERF_PROP_SAMPLE_*` properties are tracked as flags
 * @single_context: Whether a single or all gpu contexts should be monitored
 * @ctx_handle: A gem ctx handle for use with @single_context
 * @metrics_set: An ID for an OA unit metric set advertised via sysfs
 * @oa_format: An OA unit HW report format
 * @oa_periodic: Whether to enable periodic OA unit sampling
 * @oa_period_exponent: The OA unit sampling period is derived from this
 * @cs_mode: Whether the stream is configured to enable collection of metrics
 * associated with command stream of a particular GPU engine
 * @engine: The GPU engine associated with the stream in case cs_mode is enabled
 *
 * As read_properties_unlocked() enumerates and validates the properties given
 * to open a stream of metrics the configuration is built up in the structure
 * which starts out zero initialized.
 */
struct perf_open_properties {
	u32 sample_flags;

	u64 single_context:1;
	u64 ctx_handle;

	/* OA sampling state */
	int metrics_set;
	int oa_format;
	bool oa_periodic;
	int oa_period_exponent;

	/* Command stream mode */
	bool cs_mode;
	enum intel_engine_id engine;
};

/**
 * i915_perf_command_stream_hook - Insert the commands to capture metrics into the
 * command stream of a GPU engine.
 * @request: request in whose context the metrics are being collected.
 *
 * The function provides a hook through which the commands to capture perf
 * metrics, are inserted into the command stream of a GPU engine.
 */
void i915_perf_command_stream_hook(struct drm_i915_gem_request *request,
					u32 tag)
{
	struct intel_engine_cs *engine = request->engine;
	struct drm_i915_private *dev_priv = engine->i915;
	struct i915_perf_stream *stream;

	if (!dev_priv->perf.initialized)
		return;

	mutex_lock(&dev_priv->perf.streams_lock);
	list_for_each_entry(stream, &dev_priv->perf.streams, link) {
		if ((stream->state == I915_PERF_STREAM_ENABLED) &&
			stream->cs_mode && (stream->engine == engine->id))
			stream->ops->command_stream_hook(stream, request, tag);
	}
	mutex_unlock(&dev_priv->perf.streams_lock);
}

/**
 * release_perf_samples - Release old perf samples to make space for new
 * sample data.
 * @stream: An i915-perf stream associated with the samples
 * @target_size: Space required to be freed up.
 *
 * We also dereference the associated request before deleting the sample.
 * Also, no need to check whether the commands associated with old samples
 * have been completed. This is because these sample entries are anyways going
 * to be replaced by a new sample, and gpu will eventually overwrite the buffer
 * contents, when the request associated with new sample completes.
 */
static void release_perf_samples(struct i915_perf_stream *stream,
					u32 target_size)
{
	struct drm_i915_private *dev_priv = stream->dev_priv;
	struct i915_perf_cs_sample *sample, *next;
	u32 size = 0;

	list_for_each_entry_safe (sample, next,
			&dev_priv->perf.cs_samples[stream->engine], link) {

		size += sample->size;
		i915_gem_request_put(sample->request);
		list_del(&sample->link);
		kfree(sample);

		if (size >= target_size)
			break;
	}
}

/**
 * insert_perf_sample - Insert a perf sample entry to the sample list.
 * @dev_priv: i915 device private
 * @sample: perf CS sample to be inserted into the list
 *
 * This function never fails, since it always manages to insert the sample.
 * If the space is exhausted in the buffer, it will remove the older
 * entries in order to make space.
 */
static void insert_perf_sample(struct i915_perf_stream *stream,
				struct i915_perf_cs_sample *sample)
{
	struct drm_i915_private *dev_priv = stream->dev_priv;
	struct i915_perf_cs_sample *first, *last;
	u32 sample_flags = stream->sample_flags;
	enum intel_engine_id id = stream->engine;
	int max_offset =
		dev_priv->perf.command_stream_buf[id].vma->obj->base.size;
	u32 offset, sample_size = 0;
	bool sample_ts = false;

	if (stream->sample_flags & SAMPLE_OA_REPORT)
		sample_size += dev_priv->perf.oa.oa_buffer.format_size;
	else if (sample_flags & SAMPLE_TS) {
		/*
		 * XXX: Since TS data can anyways be derived from OA report, so
		 * no need to capture it for RCS engine, if capture oa data is
		 * called already.
		 */
		sample_size += I915_PERF_TS_SAMPLE_SIZE;
		sample_ts = true;
	}

	spin_lock(&dev_priv->perf.sample_lock[id]);
	if (list_empty(&dev_priv->perf.cs_samples[id])) {
		offset = 0;
		goto out;
	}

	first = list_first_entry(&dev_priv->perf.cs_samples[id],typeof(*first),
				link);
	last = list_last_entry(&dev_priv->perf.cs_samples[id], typeof(*last),
				link);

	if (last->start_offset >= first->start_offset) {
		/* Sufficient space available at the end of buffer? */
		if (last->start_offset + last->size + sample_size < max_offset)
			offset = last->start_offset + last->size;
		/*
		 * Wraparound condition. Is sufficient space available at
		 * beginning of buffer?
		 */
		else if (sample_size < first->start_offset)
			offset = 0;
		/* Insufficient space. Overwrite existing old entries */
		else {
			u32 target_size = sample_size - first->start_offset;

			dev_priv->perf.command_stream_buf[id].status |=
				I915_PERF_CMD_STREAM_BUF_STATUS_OVERFLOW;
			release_perf_samples(stream, target_size);
			offset = 0;
		}
	} else {
		/* Sufficient space available? */
		if (last->start_offset + last->size + sample_size
						< first->start_offset)
			offset = last->start_offset + last->size;
		/* Insufficient space. Overwrite existing old entries */
		else {
			u32 target_size = sample_size -
				(first->start_offset - last->start_offset -
				last->size);

			dev_priv->perf.command_stream_buf[id].status |=
				I915_PERF_CMD_STREAM_BUF_STATUS_OVERFLOW;
			release_perf_samples(stream, target_size);
			offset = last->start_offset + last->size;
		}
	}

out:
	sample->start_offset = offset;
	sample->size = sample_size;
	if (stream->sample_flags & SAMPLE_OA_REPORT) {
		sample->oa_offset = offset;
		/* Ensure 64 byte alignment of oa_offset */
		sample->oa_offset = ALIGN(sample->oa_offset, OA_ADDR_ALIGN);
		offset = sample->oa_offset +
				dev_priv->perf.oa.oa_buffer.format_size;
	}
	if (sample_ts) {
		sample->ts_offset = offset;
		/* Ensure 8 byte alignment of ts_offset */
		sample->ts_offset = ALIGN(sample->ts_offset, TS_ADDR_ALIGN);
		offset = sample->ts_offset + I915_PERF_TS_SAMPLE_SIZE;
	}

	list_add_tail(&sample->link, &dev_priv->perf.cs_samples[id]);

	spin_unlock(&dev_priv->perf.sample_lock[id]);
}

/**
 * i915_engine_stream_capture_oa - Insert the commands to capture OA reports
 * into the render command stream
 * @request: request in whose context the OA metrics are being collected.
 * @offset: command stream buffer offset where the OA metrics need to be
 * collected
 */
static int i915_engine_stream_capture_oa(struct drm_i915_gem_request *request,
					u32 offset)
{
	struct drm_i915_private *dev_priv = request->i915;
	u32 addr = 0;
	u32 cmd, *cs;

	addr = dev_priv->perf.command_stream_buf[RCS].vma->node.start + offset;

	if (WARN_ON(addr & 0x3f)) {
		DRM_ERROR("OA buffer address not aligned to 64 byte");
		return -EINVAL;
	}

	cs = intel_ring_begin(request, 4);
	if (IS_ERR(cs))
		return PTR_ERR(cs);

	cmd = MI_REPORT_PERF_COUNT | (1<<0);
	if (INTEL_GEN(dev_priv) >= 8)
		cmd |= (2<<0);

	*cs++ = cmd;
	*cs++ = addr | MI_REPORT_PERF_COUNT_GGTT;
	*cs++ = request->global_seqno;

	if (INTEL_GEN(dev_priv) >= 8)
		*cs++ = 0;
	else
		*cs++ = MI_NOOP;

	intel_ring_advance(request, cs);

	return 0;
}

/**
 * i915_engine_stream_capture_ts - Insert the commands to capture timestamp
 * data into the GPU command stream
 * @request: request in whose context the timestamps are being collected.
 * @offset: command stream buffer offset where the timestamp data needs to be
 * collected
 */
static int i915_engine_stream_capture_ts(struct drm_i915_gem_request *request,
						u32 offset)
{
	struct drm_i915_private *dev_priv = request->i915;
	enum intel_engine_id id = request->engine->id;
	u32 addr = 0;
	u32 cmd, *cs;

	cs = intel_ring_begin(request, 6);
	if (IS_ERR(cs))
		return PTR_ERR(cs);

	addr = dev_priv->perf.command_stream_buf[id].vma->node.start + offset;

	if (id == RCS) {
		if (INTEL_GEN(dev_priv) >= 8)
			cmd = GFX_OP_PIPE_CONTROL(6);
		else
			cmd = GFX_OP_PIPE_CONTROL(5);

		*cs++ = cmd;
		*cs++ = PIPE_CONTROL_GLOBAL_GTT_IVB |
				PIPE_CONTROL_TIMESTAMP_WRITE;
		*cs++ = addr | PIPE_CONTROL_GLOBAL_GTT;
		*cs++ = 0;
		*cs++ = 0;

		if (INTEL_GEN(dev_priv) >= 8)
			*cs++ = 0;
		else
			*cs++ = MI_NOOP;
	} else {
		uint32_t cmd;

		cmd = MI_FLUSH_DW + 1;
		if (INTEL_GEN(dev_priv) >= 8)
			cmd += 1;

		cmd |= MI_FLUSH_DW_OP_STAMP;

		*cs++ = cmd;
		*cs++ = addr | MI_FLUSH_DW_USE_GTT;
		*cs++ = 0;
		*cs++ = 0;

		if (INTEL_GEN(dev_priv) >= 8)
			*cs++ = 0;
		else
			*cs++ = MI_NOOP;
		*cs++ = MI_NOOP;
	}
	intel_ring_advance(request, cs);

	return 0;
}

/**
 * i915_engine_stream_capture_cs_data - Insert the commands to capture perf
 * metrics into the GPU command stream
 * @stream: An i915-perf stream opened for GPU metrics
 * @request: request in whose context the metrics are being collected.
 * @tag: userspace provided tag to be associated with the perf sample
 */
static void i915_engine_stream_capture_cs_data(struct i915_perf_stream *stream,
					struct drm_i915_gem_request *request,
					u32 tag)
{
	struct drm_i915_private *dev_priv = request->i915;
	struct i915_gem_context *ctx = request->ctx;
	struct i915_perf_cs_sample *sample;
	enum intel_engine_id id = stream->engine;
	u32 sample_flags = stream->sample_flags;
	int ret;

	sample = kzalloc(sizeof(*sample), GFP_KERNEL);
	if (sample == NULL) {
		DRM_ERROR("Perf sample alloc failed\n");
		return;
	}

	sample->ctx_id = ctx->hw_id;
	sample->pid = current->pid;
	sample->tag = tag;
	i915_gem_request_assign(&sample->request, request);

	insert_perf_sample(stream, sample);

	if (sample_flags & SAMPLE_OA_REPORT) {
		ret = i915_engine_stream_capture_oa(request, sample->oa_offset);
		if (ret)
			goto err_unref;
	} else if (sample_flags & SAMPLE_TS) {
		/*
		 * XXX: Since TS data can anyways be derived from OA report, so
		 * no need to capture it for RCS engine, if capture oa data is
		 * called already.
		 */
		ret = i915_engine_stream_capture_ts(request, sample->ts_offset);
		if (ret)
			goto err_unref;
	}

	i915_gem_active_set(&stream->last_request, request);
	i915_vma_move_to_active(dev_priv->perf.command_stream_buf[id].vma,
					request, EXEC_OBJECT_WRITE);
	return;

err_unref:
	i915_gem_request_put(sample->request);
	spin_lock(&dev_priv->perf.sample_lock[id]);
	list_del(&sample->link);
	spin_unlock(&dev_priv->perf.sample_lock[id]);
	kfree(sample);
}

/**
 * i915_engine_stream_release_samples - Release the perf command stream samples
 * @stream: An i915-perf stream opened for GPU metrics
 *
 * Note: The associated requests should be completed before releasing the
 * references here.
 */
static void i915_engine_stream_release_samples(struct i915_perf_stream *stream)
{
	struct drm_i915_private *dev_priv = stream->dev_priv;
	enum intel_engine_id id = stream->engine;
	struct i915_perf_cs_sample *entry, *next;

	list_for_each_entry_safe
		(entry, next, &dev_priv->perf.cs_samples[id], link) {
		i915_gem_request_put(entry->request);

		spin_lock(&dev_priv->perf.sample_lock[id]);
		list_del(&entry->link);
		spin_unlock(&dev_priv->perf.sample_lock[id]);
		kfree(entry);
	}
}

/**
 * gen8_oa_buffer_num_reports_unlocked - check for data and update tail ptr state
 * @dev_priv: i915 device instance
 *
 * This is either called via fops (for blocking reads in user ctx) or the poll
 * check hrtimer (atomic ctx) to check the OA buffer tail pointer and check
 * if there is data available for userspace to read.
 *
 * This function is central to providing a workaround for the OA unit tail
 * pointer having a race with respect to what data is visible to the CPU.
 * It is responsible for reading tail pointers from the hardware and giving
 * the pointers time to 'age' before they are made available for reading.
 * (See description of OA_TAIL_MARGIN_NSEC above for further details.)
 *
 * Besides returning num of reports when there is data available to read() it
 * also has the side effect of updating the oa_buffer.tails[], .aging_timestamp
 * and .aged_tail_idx state used for reading.
 *
 * Note: It's safe to read OA config state here unlocked, assuming that this is
 * only called while the stream is enabled, while the global OA configuration
 * can't be modified.
 *
 * Returns: number of samples available to read
 */
static u32 gen8_oa_buffer_num_reports_unlocked(
			struct drm_i915_private *dev_priv, u32 *last_ts)
{
	int report_size = dev_priv->perf.oa.oa_buffer.format_size;
	unsigned long flags;
	unsigned int aged_idx;
	u32 head, hw_tail, aged_tail, aging_tail, num_reports = 0;
	u64 now;

	/* We have to consider the (unlikely) possibility that read() errors
	 * could result in an OA buffer reset which might reset the head,
	 * tails[] and aged_tail state.
	 */
	spin_lock_irqsave(&dev_priv->perf.oa.oa_buffer.ptr_lock, flags);

	/* NB: The head we observe here might effectively be a little out of
	 * date (between head and tails[aged_idx].offset if there is currently
	 * a read() in progress.
	 */
	head = dev_priv->perf.oa.oa_buffer.head;

	aged_idx = dev_priv->perf.oa.oa_buffer.aged_tail_idx;
	aged_tail = dev_priv->perf.oa.oa_buffer.tails[aged_idx].offset;
	aging_tail = dev_priv->perf.oa.oa_buffer.tails[!aged_idx].offset;

	hw_tail = I915_READ(GEN8_OATAILPTR) & GEN8_OATAILPTR_MASK;

	/* The tail pointer increases in 64 byte increments,
	 * not in report_size steps...
	 */
	hw_tail &= ~(report_size - 1);

	now = ktime_get_mono_fast_ns();

	/* Update the aged tail
	 *
	 * Flip the tail pointer available for read()s once the aging tail is
	 * old enough to trust that the corresponding data will be visible to
	 * the CPU...
	 *
	 * Do this before updating the aging pointer in case we may be able to
	 * immediately start aging a new pointer too (if new data has become
	 * available) without needing to wait for a later hrtimer callback.
	 */
	if (aging_tail != INVALID_TAIL_PTR &&
	    ((now - dev_priv->perf.oa.oa_buffer.aging_timestamp) >
	     OA_TAIL_MARGIN_NSEC)) {
		u32 mask = (OA_BUFFER_SIZE - 1);
		u32 gtt_offset = i915_ggtt_offset(
				dev_priv->perf.oa.oa_buffer.vma);
		u32 head = (dev_priv->perf.oa.oa_buffer.head - gtt_offset)
				& mask;
		u8 *oa_buf_base = dev_priv->perf.oa.oa_buffer.vaddr;
		u32 *report32;

		aged_idx ^= 1;
		dev_priv->perf.oa.oa_buffer.aged_tail_idx = aged_idx;

		aged_tail = aging_tail;

		/* Mark that we need a new pointer to start aging... */
		dev_priv->perf.oa.oa_buffer.tails[!aged_idx].offset = INVALID_TAIL_PTR;
		aging_tail = INVALID_TAIL_PTR;

		num_reports = OA_TAKEN(((aged_tail - gtt_offset) & mask), head)/
				report_size;

		/* read the timestamp of last OA report */
		head = (head + report_size*(num_reports - 1)) & mask;
		report32 = (u32 *)(oa_buf_base + head);
		*last_ts = report32[1];
	}

	/* Update the aging tail
	 *
	 * We throttle aging tail updates until we have a new tail that
	 * represents >= one report more data than is already available for
	 * reading. This ensures there will be enough data for a successful
	 * read once this new pointer has aged and ensures we will give the new
	 * pointer time to age.
	 */
	if (aging_tail == INVALID_TAIL_PTR &&
	    (aged_tail == INVALID_TAIL_PTR ||
	     OA_TAKEN(hw_tail, aged_tail) >= report_size)) {
		struct i915_vma *vma = dev_priv->perf.oa.oa_buffer.vma;
		u32 gtt_offset = i915_ggtt_offset(vma);

		/* Be paranoid and do a bounds check on the pointer read back
		 * from hardware, just in case some spurious hardware condition
		 * could put the tail out of bounds...
		 */
		if (hw_tail >= gtt_offset &&
		    hw_tail < (gtt_offset + OA_BUFFER_SIZE)) {
			dev_priv->perf.oa.oa_buffer.tails[!aged_idx].offset =
				aging_tail = hw_tail;
			dev_priv->perf.oa.oa_buffer.aging_timestamp = now;
		} else {
			DRM_ERROR("Ignoring spurious out of range OA buffer tail pointer = %u\n",
				  hw_tail);
		}
	}

	spin_unlock_irqrestore(&dev_priv->perf.oa.oa_buffer.ptr_lock, flags);

	return aged_tail == INVALID_TAIL_PTR ? 0 : num_reports;
}

/**
 * gen7_oa_buffer_num_reports_unlocked - check for data and update tail ptr state
 * @dev_priv: i915 device instance
 *
 * This is either called via fops (for blocking reads in user ctx) or the poll
 * check hrtimer (atomic ctx) to check the OA buffer tail pointer and check
 * if there is data available for userspace to read.
 *
 * This function is central to providing a workaround for the OA unit tail
 * pointer having a race with respect to what data is visible to the CPU.
 * It is responsible for reading tail pointers from the hardware and giving
 * the pointers time to 'age' before they are made available for reading.
 * (See description of OA_TAIL_MARGIN_NSEC above for further details.)
 *
 * Besides returning num of reports when there is data available to read() it
 * also has the side effect of updating the oa_buffer.tails[], .aging_timestamp
 * and .aged_tail_idx state used for reading.
 *
 * Note: It's safe to read OA config state here unlocked, assuming that this is
 * only called while the stream is enabled, while the global OA configuration
 * can't be modified.
 *
 * Returns: number of samples available to read
 */
static u32 gen7_oa_buffer_num_reports_unlocked(
			struct drm_i915_private *dev_priv, u32 *last_ts)
{
	int report_size = dev_priv->perf.oa.oa_buffer.format_size;
	unsigned long flags;
	unsigned int aged_idx;
	u32 oastatus1;
	u32 head, hw_tail, aged_tail, aging_tail, num_reports = 0;
	u64 now;

	/* We have to consider the (unlikely) possibility that read() errors
	 * could result in an OA buffer reset which might reset the head,
	 * tails[] and aged_tail state.
	 */
	spin_lock_irqsave(&dev_priv->perf.oa.oa_buffer.ptr_lock, flags);

	/* NB: The head we observe here might effectively be a little out of
	 * date (between head and tails[aged_idx].offset if there is currently
	 * a read() in progress.
	 */
	head = dev_priv->perf.oa.oa_buffer.head;

	aged_idx = dev_priv->perf.oa.oa_buffer.aged_tail_idx;
	aged_tail = dev_priv->perf.oa.oa_buffer.tails[aged_idx].offset;
	aging_tail = dev_priv->perf.oa.oa_buffer.tails[!aged_idx].offset;

	oastatus1 = I915_READ(GEN7_OASTATUS1);
	hw_tail = oastatus1 & GEN7_OASTATUS1_TAIL_MASK;

	/* The tail pointer increases in 64 byte increments,
	 * not in report_size steps...
	 */
	hw_tail &= ~(report_size - 1);

	now = ktime_get_mono_fast_ns();

	/* Update the aged tail
	 *
	 * Flip the tail pointer available for read()s once the aging tail is
	 * old enough to trust that the corresponding data will be visible to
	 * the CPU...
	 *
	 * Do this before updating the aging pointer in case we may be able to
	 * immediately start aging a new pointer too (if new data has become
	 * available) without needing to wait for a later hrtimer callback.
	 */
	if (aging_tail != INVALID_TAIL_PTR &&
	    ((now - dev_priv->perf.oa.oa_buffer.aging_timestamp) >
	     OA_TAIL_MARGIN_NSEC)) {
		u32 mask = (OA_BUFFER_SIZE - 1);
		u32 gtt_offset = i915_ggtt_offset(
				dev_priv->perf.oa.oa_buffer.vma);
		u32 head = (dev_priv->perf.oa.oa_buffer.head - gtt_offset)
				& mask;
		u8 *oa_buf_base = dev_priv->perf.oa.oa_buffer.vaddr;
		u32 *report32;

		aged_idx ^= 1;
		dev_priv->perf.oa.oa_buffer.aged_tail_idx = aged_idx;

		aged_tail = aging_tail;

		/* Mark that we need a new pointer to start aging... */
		dev_priv->perf.oa.oa_buffer.tails[!aged_idx].offset = INVALID_TAIL_PTR;
		aging_tail = INVALID_TAIL_PTR;

		num_reports = OA_TAKEN(((aged_tail - gtt_offset) & mask), head)/
				report_size;

		/* read the timestamp of last OA report */
		head = (head + report_size*(num_reports - 1)) & mask;
		report32 = (u32 *)(oa_buf_base + head);
		*last_ts = report32[1];
	}

	/* Update the aging tail
	 *
	 * We throttle aging tail updates until we have a new tail that
	 * represents >= one report more data than is already available for
	 * reading. This ensures there will be enough data for a successful
	 * read once this new pointer has aged and ensures we will give the new
	 * pointer time to age.
	 */
	if (aging_tail == INVALID_TAIL_PTR &&
	    (aged_tail == INVALID_TAIL_PTR ||
	     OA_TAKEN(hw_tail, aged_tail) >= report_size)) {
		struct i915_vma *vma = dev_priv->perf.oa.oa_buffer.vma;
		u32 gtt_offset = i915_ggtt_offset(vma);

		/* Be paranoid and do a bounds check on the pointer read back
		 * from hardware, just in case some spurious hardware condition
		 * could put the tail out of bounds...
		 */
		if (hw_tail >= gtt_offset &&
		    hw_tail < (gtt_offset + OA_BUFFER_SIZE)) {
			dev_priv->perf.oa.oa_buffer.tails[!aged_idx].offset =
				aging_tail = hw_tail;
			dev_priv->perf.oa.oa_buffer.aging_timestamp = now;
		} else {
			DRM_ERROR("Ignoring spurious out of range OA buffer tail pointer = %u\n",
				  hw_tail);
		}
	}

	spin_unlock_irqrestore(&dev_priv->perf.oa.oa_buffer.ptr_lock, flags);

	return aged_tail == INVALID_TAIL_PTR ? 0 : num_reports;
}

static u32 gen7_oa_buffer_get_ctx_id(struct i915_perf_stream *stream,
				    const u8 *report)
{
	struct drm_i915_private *dev_priv = stream->dev_priv;

	if (!stream->cs_mode)
		WARN_ONCE(1,
			"CTX ID can't be retrieved if command stream mode not enabled");

	/*
	 * OA reports generated in Gen7 don't have the ctx ID information.
	 * Therefore, just rely on the ctx ID information from the last CS
	 * sample forwarded
	 */
	return dev_priv->perf.last_cmd_stream_ctx_id;
}

static u32 gen8_oa_buffer_get_ctx_id(struct i915_perf_stream *stream,
				    const u8 *report)
{
	struct drm_i915_private *dev_priv = stream->dev_priv;

	/* The ctx ID present in the OA reports have intel_context::hw_id
	 * present, since this is programmed into the ELSP in execlist mode.
	 * In non-execlist mode, fall back to retrieving the ctx ID from the
	 * last saved ctx ID from command stream mode.
	 */
	if (i915.enable_execlists) {
		u32 *report32 = (void *)report;
		u32 ctx_id = report32[2] & 0x1fffff;
		return ctx_id;
	} else {
		if (!stream->cs_mode)
		WARN_ONCE(1,
			"CTX ID can't be retrieved if command stream mode not enabled");

		return dev_priv->perf.last_cmd_stream_ctx_id;
	}
}

/**
 * append_oa_status - Appends a status record to a userspace read() buffer.
 * @stream: An i915-perf stream opened for OA metrics
 * @buf: destination buffer given by userspace
 * @count: the number of bytes userspace wants to read
 * @offset: (inout): the current position for writing into @buf
 * @type: The kind of status to report to userspace
 *
 * Writes a status record (such as `DRM_I915_PERF_RECORD_OA_REPORT_LOST`)
 * into the userspace read() buffer.
 *
 * The @buf @offset will only be updated on success.
 *
 * Returns: 0 on success, negative error code on failure.
 */
static int append_oa_status(struct i915_perf_stream *stream,
			    char __user *buf,
			    size_t count,
			    size_t *offset,
			    enum drm_i915_perf_record_type type)
{
	struct drm_i915_perf_record_header header = { type, 0, sizeof(header) };

	if ((count - *offset) < header.size)
		return -ENOSPC;

	if (copy_to_user(buf + *offset, &header, sizeof(header)))
		return -EFAULT;

	(*offset) += header.size;

	return 0;
}

/**
 * append_sample - Copies single perf sample into userspace read() buffer.
 * @stream: An i915-perf stream opened for perf samples
 * @buf: destination buffer given by userspace
 * @count: the number of bytes userspace wants to read
 * @offset: (inout): the current position for writing into @buf
 * @data: perf sample data which contains (optionally) metrics configured
 * earlier when opening a stream
 *
 * The contents of a sample are configured through `DRM_I915_PERF_PROP_SAMPLE_*`
 * properties when opening a stream, tracked as `stream->sample_flags`. This
 * function copies the requested components of a single sample to the given
 * read() @buf.
 *
 * The @buf @offset will only be updated on success.
 *
 * Returns: 0 on success, negative error code on failure.
 */
static int append_sample(struct i915_perf_stream *stream,
			    char __user *buf,
			    size_t count,
			    size_t *offset,
			    const struct sample_data *data)
{
	struct drm_i915_private *dev_priv = stream->dev_priv;
	int report_size = dev_priv->perf.oa.oa_buffer.format_size;
	struct drm_i915_perf_record_header header;
	u32 sample_flags = stream->sample_flags;

	header.type = DRM_I915_PERF_RECORD_SAMPLE;
	header.pad = 0;
	header.size = stream->sample_size;

	if ((count - *offset) < header.size)
		return -ENOSPC;

	buf += *offset;
	if (copy_to_user(buf, &header, sizeof(header)))
		return -EFAULT;
	buf += sizeof(header);

	if (sample_flags & SAMPLE_OA_SOURCE_INFO) {
		if (copy_to_user(buf, &data->source, 4))
			return -EFAULT;
		buf += 4;
	}

	if (sample_flags & SAMPLE_CTX_ID) {
		if (copy_to_user(buf, &data->ctx_id, 4))
			return -EFAULT;
		buf += 4;
	}

	if (sample_flags & SAMPLE_PID) {
		if (copy_to_user(buf, &data->pid, 4))
			return -EFAULT;
		buf += 4;
	}

	if (sample_flags & SAMPLE_TAG) {
		if (copy_to_user(buf, &data->tag, 4))
			return -EFAULT;
		buf += 4;
	}

	if (sample_flags & SAMPLE_TS) {
		if (copy_to_user(buf, &data->ts, I915_PERF_TS_SAMPLE_SIZE))
			return -EFAULT;
		buf += I915_PERF_TS_SAMPLE_SIZE;
	}

	if (sample_flags & SAMPLE_OA_REPORT) {
		if (copy_to_user(buf, data->report, report_size))
			return -EFAULT;
		buf += report_size;
	}

	(*offset) += header.size;

	return 0;
}

/**
 * get_gpu_ts_from_oa_report - Retrieve absolute gpu timestamp from OA report
 *
 * Note: We are assuming that we're updating last_gpu_ts frequently enough so
 * that it's never possible to see multiple overflows before we compare
 * sample_ts to last_gpu_ts. Since this is significantly large duration
 * (~6min for 80ns ts base), we can safely assume so.
 */
static u64 get_gpu_ts_from_oa_report(struct drm_i915_private *dev_priv,
					const u8 *report)
{
	u32 sample_ts = *(u32 *)(report + 4);
	u32 delta;

	delta = sample_ts - (u32)dev_priv->perf.oa.last_gpu_ts;
	dev_priv->perf.oa.last_gpu_ts += delta;

	return dev_priv->perf.oa.last_gpu_ts;
}

/**
 * append_oa_buffer_sample - Copies single periodic OA report into userspace
 * read() buffer.
 * @stream: An i915-perf stream opened for OA metrics
 * @buf: destination buffer given by userspace
 * @count: the number of bytes userspace wants to read
 * @offset: (inout): the current position for writing into @buf
 * @report: A single OA report to (optionally) include as part of the sample
 *
 * Returns: 0 on success, negative error code on failure.
 */
static int append_oa_buffer_sample(struct i915_perf_stream *stream,
				char __user *buf, size_t count,
				size_t *offset,	const u8 *report)
{
	struct drm_i915_private *dev_priv =  stream->dev_priv;
	u32 sample_flags = stream->sample_flags;
	struct sample_data data = { 0 };

	if (sample_flags & SAMPLE_OA_SOURCE_INFO)
		data.source = I915_PERF_OA_EVENT_SOURCE_PERIODIC;

	if (sample_flags & SAMPLE_CTX_ID)
		data.ctx_id = dev_priv->perf.oa.ops.get_ctx_id(stream, report);

	if (sample_flags & SAMPLE_PID)
		data.pid = dev_priv->perf.last_pid;

	if (sample_flags & SAMPLE_TAG)
		data.tag = dev_priv->perf.last_tag;

	if (sample_flags & SAMPLE_TS)
		data.ts = get_gpu_ts_from_oa_report(dev_priv, report);

	if (sample_flags & SAMPLE_OA_REPORT)
		data.report = report;

	return append_sample(stream, buf, count, offset, &data);
}


/**
 * Copies all buffered OA reports into userspace read() buffer.
 * @stream: An i915-perf stream opened for OA metrics
 * @buf: destination buffer given by userspace
 * @count: the number of bytes userspace wants to read
 * @offset: (inout): the current position for writing into @buf
 * @ts: copy OA reports till this timestamp
 * @max_reports: max number of OA reports to copy
 *
 * Notably any error condition resulting in a short read (-%ENOSPC or
 * -%EFAULT) will be returned even though one or more records may
 * have been successfully copied. In this case it's up to the caller
 * to decide if the error should be squashed before returning to
 * userspace.
 *
 * Note: reports are consumed from the head, and appended to the
 * tail, so the tail chases the head?... If you think that's mad
 * and back-to-front you're not alone, but this follows the
 * Gen PRM naming convention.
 *
 * Returns: 0 on success, negative error code on failure.
 */
static int gen8_append_oa_reports(struct i915_perf_stream *stream,
				  char __user *buf,
				  size_t count,
				  size_t *offset,
				  u32 ts,
				  u32 max_reports)
{
	struct drm_i915_private *dev_priv = stream->dev_priv;
	int report_size = dev_priv->perf.oa.oa_buffer.format_size;
	u8 *oa_buf_base = dev_priv->perf.oa.oa_buffer.vaddr;
	u32 gtt_offset = i915_ggtt_offset(dev_priv->perf.oa.oa_buffer.vma);
	u32 mask = (OA_BUFFER_SIZE - 1);
	size_t start_offset = *offset;
	unsigned long flags;
	unsigned int aged_tail_idx;
	u32 head, tail;
	u32 taken;
	int ret = 0;
	u32 report_count = 0;

	if (WARN_ON(stream->state != I915_PERF_STREAM_ENABLED))
		return -EIO;

	spin_lock_irqsave(&dev_priv->perf.oa.oa_buffer.ptr_lock, flags);

	head = dev_priv->perf.oa.oa_buffer.head;
	aged_tail_idx = dev_priv->perf.oa.oa_buffer.aged_tail_idx;
	tail = dev_priv->perf.oa.oa_buffer.tails[aged_tail_idx].offset;

	spin_unlock_irqrestore(&dev_priv->perf.oa.oa_buffer.ptr_lock, flags);

	/* An invalid tail pointer here means we're still waiting for the poll
	 * hrtimer callback to give us a pointer
	 */
	if (tail == INVALID_TAIL_PTR)
		return -EAGAIN;

	/* NB: oa_buffer.head/tail include the gtt_offset which we don't want
	 * while indexing relative to oa_buf_base.
	 */
	head -= gtt_offset;
	tail -= gtt_offset;

	/* An out of bounds or misaligned head or tail pointer implies a driver
	 * bug since we validate + align the tail pointers we read from the
	 * hardware and we are in full control of the head pointer which should
	 * only be incremented by multiples of the report size (notably also
	 * all a power of two).
	 */
	if (WARN_ONCE(head > OA_BUFFER_SIZE || head % report_size ||
		      tail > OA_BUFFER_SIZE || tail % report_size,
		      "Inconsistent OA buffer pointers: head = %u, tail = %u\n",
		      head, tail))
		return -EIO;


	for (/* none */;
	     (taken = OA_TAKEN(tail, head)) && (report_count <= max_reports);
	     head = (head + report_size) & mask) {
		u8 *report = oa_buf_base + head;
		u32 *report32 = (void *)report;
		u32 ctx_id;
		u32 reason;
		u32 report_ts = report32[1];

		/* Report timestamp should not exceed the given ts */
		if (report_ts > ts)
			break;

		/* All the report sizes factor neatly into the buffer
		 * size so we never expect to see a report split
		 * between the beginning and end of the buffer.
		 *
		 * Given the initial alignment check a misalignment
		 * here would imply a driver bug that would result
		 * in an overrun.
		 */
		if (WARN_ON((OA_BUFFER_SIZE - head) < report_size)) {
			DRM_ERROR("Spurious OA head ptr: non-integral report offset\n");
			break;
		}

		/* The reason field includes flags identifying what
		 * triggered this specific report (mostly timer
		 * triggered or e.g. due to a context switch).
		 *
		 * This field is never expected to be zero so we can
		 * check that the report isn't invalid before copying
		 * it to userspace...
		 */
		reason = ((report32[0] >> OAREPORT_REASON_SHIFT) &
			  OAREPORT_REASON_MASK);
		if (reason == 0) {
			if (printk_ratelimit())
				DRM_NOTE("Skipping spurious, invalid OA report\n");
			continue;
		}

		/* XXX: Just keep the lower 21 bits for now since I'm not
		 * entirely sure if the HW touches any of the higher bits in
		 * this field
		 */
		ctx_id = report32[2] & 0x1fffff;

		/* Squash whatever is in the CTX_ID field if it's
		 * marked as invalid to be sure we avoid
		 * false-positive, single-context filtering below...
		 */
		if (!(report32[0] & dev_priv->perf.oa.gen8_valid_ctx_bit))
			ctx_id = report32[2] = INVALID_CTX_ID;

		/* NB: For Gen 8 the OA unit no longer supports clock gating
		 * off for a specific context and the kernel can't securely
		 * stop the counters from updating as system-wide / global
		 * values.
		 *
		 * Automatic reports now include a context ID so reports can be
		 * filtered on the cpu but it's not worth trying to
		 * automatically subtract/hide counter progress for other
		 * contexts while filtering since we can't stop userspace
		 * issuing MI_REPORT_PERF_COUNT commands which would still
		 * provide a side-band view of the real values.
		 *
		 * To allow userspace (such as Mesa/GL_INTEL_performance_query)
		 * to normalize counters for a single filtered context then it
		 * needs be forwarded bookend context-switch reports so that it
		 * can track switches in between MI_REPORT_PERF_COUNT commands
		 * and can itself subtract/ignore the progress of counters
		 * associated with other contexts. Note that the hardware
		 * automatically triggers reports when switching to a new
		 * context which are tagged with the ID of the newly active
		 * context. To avoid the complexity (and likely fragility) of
		 * reading ahead while parsing reports to try and minimize
		 * forwarding redundant context switch reports (i.e. between
		 * other, unrelated contexts) we simply elect to forward them
		 * all.
		 *
		 * We don't rely solely on the reason field to identify context
		 * switches since it's not-uncommon for periodic samples to
		 * identify a switch before any 'context switch' report.
		 */
		if (!stream->ctx ||
		    dev_priv->perf.oa.specific_ctx_id == ctx_id ||
		    (dev_priv->perf.oa.oa_buffer.last_ctx_id ==
		     dev_priv->perf.oa.specific_ctx_id) ||
		    reason & OAREPORT_REASON_CTX_SWITCH) {

			/* While filtering for a single context we avoid
			 * leaking the IDs of other contexts.
			 */
			if (stream->ctx &&
			    dev_priv->perf.oa.specific_ctx_id != ctx_id) {
				report32[2] = INVALID_CTX_ID;
			}

			ret = append_oa_buffer_sample(stream, buf, count,
							offset, report);
			if (ret)
				break;

			report_count++;
			dev_priv->perf.oa.oa_buffer.last_ctx_id = ctx_id;
		}

		/* The above reason field sanity check is based on
		 * the assumption that the OA buffer is initially
		 * zeroed and we reset the field after copying so the
		 * check is still meaningful once old reports start
		 * being overwritten.
		 */
		report32[0] = 0;
	}

	if (start_offset != *offset) {
		spin_lock_irqsave(&dev_priv->perf.oa.oa_buffer.ptr_lock, flags);

		/* We removed the gtt_offset for the copy loop above, indexing
		 * relative to oa_buf_base so put back here...
		 */
		head += gtt_offset;

		I915_WRITE(GEN8_OAHEADPTR, head & GEN8_OAHEADPTR_MASK);
		dev_priv->perf.oa.oa_buffer.head = head;

		spin_unlock_irqrestore(&dev_priv->perf.oa.oa_buffer.ptr_lock, flags);
	}

	return ret;
}

/**
 * gen8_oa_read - copy status records then buffered OA reports
 * @stream: An i915-perf stream opened for OA metrics
 * @buf: destination buffer given by userspace
 * @count: the number of bytes userspace wants to read
 * @offset: (inout): the current position for writing into @buf
 * @ts: copy OA reports till this timestamp
 * @max_reports: max number of OA reports to copy
 *
 * Checks OA unit status registers and if necessary appends corresponding
 * status records for userspace (such as for a buffer full condition) and then
 * initiate appending any buffered OA reports.
 *
 * Updates @offset according to the number of bytes successfully copied into
 * the userspace buffer.
 *
 * NB: some data may be successfully copied to the userspace buffer
 * even if an error is returned, and this is reflected in the
 * updated @read_state.
 *
 * Returns: zero on success or a negative error code
 */
static int gen8_oa_read(struct i915_perf_stream *stream,
			char __user *buf,
			size_t count,
			size_t *offset,
			u32 ts,
			u32 max_reports)
{
	struct drm_i915_private *dev_priv = stream->dev_priv;
	u32 oastatus;
	int ret;

	if (WARN_ON(!dev_priv->perf.oa.oa_buffer.vaddr))
		return -EIO;

	oastatus = I915_READ(GEN8_OASTATUS);

	/* We treat OABUFFER_OVERFLOW as a significant error:
	 *
	 * Although theoretically we could handle this more gracefully
	 * sometimes, some Gens don't correctly suppress certain
	 * automatically triggered reports in this condition and so we
	 * have to assume that old reports are now being trampled
	 * over.
	 *
	 * Considering how we don't currently give userspace control
	 * over the OA buffer size and always configure a large 16MB
	 * buffer, then a buffer overflow does anyway likely indicate
	 * that something has gone quite badly wrong.
	 */
	if (oastatus & GEN8_OASTATUS_OABUFFER_OVERFLOW) {
		ret = append_oa_status(stream, buf, count, offset,
				       DRM_I915_PERF_RECORD_OA_BUFFER_LOST);
		if (ret)
			return ret;

		DRM_DEBUG("OA buffer overflow (exponent = %d): force restart\n",
			  dev_priv->perf.oa.period_exponent);

		dev_priv->perf.oa.ops.oa_disable(dev_priv);
		dev_priv->perf.oa.ops.oa_enable(dev_priv);

		/* Note: .oa_enable() is expected to re-init the oabuffer
		 * and reset GEN8_OASTATUS for us */
		oastatus = I915_READ(GEN8_OASTATUS);
	}

	if (oastatus & GEN8_OASTATUS_REPORT_LOST) {
		ret = append_oa_status(stream, buf, count, offset,
				       DRM_I915_PERF_RECORD_OA_REPORT_LOST);
		if (ret == 0) {
			I915_WRITE(GEN8_OASTATUS,
				   oastatus & ~GEN8_OASTATUS_REPORT_LOST);
		}
	}

	return gen8_append_oa_reports(stream, buf, count, offset, ts,
					max_reports);
}

/**
 * Copies all buffered OA reports into userspace read() buffer.
 * @stream: An i915-perf stream opened for OA metrics
 * @buf: destination buffer given by userspace
 * @count: the number of bytes userspace wants to read
 * @offset: (inout): the current position for writing into @buf
 * @ts: copy OA reports till this timestamp
 * @max_reports: max number of OA reports to copy
 *
 * Notably any error condition resulting in a short read (-%ENOSPC or
 * -%EFAULT) will be returned even though one or more records may
 * have been successfully copied. In this case it's up to the caller
 * to decide if the error should be squashed before returning to
 * userspace.
 *
 * Note: reports are consumed from the head, and appended to the
 * tail, so the tail chases the head?... If you think that's mad
 * and back-to-front you're not alone, but this follows the
 * Gen PRM naming convention.
 *
 * Returns: 0 on success, negative error code on failure.
 */
static int gen7_append_oa_reports(struct i915_perf_stream *stream,
				  char __user *buf,
				  size_t count,
				  size_t *offset,
				  u32 ts,
				  u32 max_reports)
{
	struct drm_i915_private *dev_priv = stream->dev_priv;
	int report_size = dev_priv->perf.oa.oa_buffer.format_size;
	u8 *oa_buf_base = dev_priv->perf.oa.oa_buffer.vaddr;
	u32 gtt_offset = i915_ggtt_offset(dev_priv->perf.oa.oa_buffer.vma);
	u32 mask = (OA_BUFFER_SIZE - 1);
	size_t start_offset = *offset;
	unsigned long flags;
	unsigned int aged_tail_idx;
	u32 head, tail;
	u32 taken;
	int ret = 0;
	u32 report_count = 0;

	if (WARN_ON(stream->state != I915_PERF_STREAM_ENABLED))
		return -EIO;

	spin_lock_irqsave(&dev_priv->perf.oa.oa_buffer.ptr_lock, flags);

	head = dev_priv->perf.oa.oa_buffer.head;
	aged_tail_idx = dev_priv->perf.oa.oa_buffer.aged_tail_idx;
	tail = dev_priv->perf.oa.oa_buffer.tails[aged_tail_idx].offset;

	spin_unlock_irqrestore(&dev_priv->perf.oa.oa_buffer.ptr_lock, flags);

	/* An invalid tail pointer here means we're still waiting for the poll
	 * hrtimer callback to give us a pointer
	 */
	if (tail == INVALID_TAIL_PTR)
		return -EAGAIN;

	/* NB: oa_buffer.head/tail include the gtt_offset which we don't want
	 * while indexing relative to oa_buf_base.
	 */
	head -= gtt_offset;
	tail -= gtt_offset;

	/* An out of bounds or misaligned head or tail pointer implies a driver
	 * bug since we validate + align the tail pointers we read from the
	 * hardware and we are in full control of the head pointer which should
	 * only be incremented by multiples of the report size (notably also
	 * all a power of two).
	 */
	if (WARN_ONCE(head > OA_BUFFER_SIZE || head % report_size ||
		      tail > OA_BUFFER_SIZE || tail % report_size,
		      "Inconsistent OA buffer pointers: head = %u, tail = %u\n",
		      head, tail))
		return -EIO;


	for (/* none */;
	     (taken = OA_TAKEN(tail, head)) && (report_count <= max_reports);
	     head = (head + report_size) & mask) {
		u8 *report = oa_buf_base + head;
		u32 *report32 = (void *)report;

		/* All the report sizes factor neatly into the buffer
		 * size so we never expect to see a report split
		 * between the beginning and end of the buffer.
		 *
		 * Given the initial alignment check a misalignment
		 * here would imply a driver bug that would result
		 * in an overrun.
		 */
		if (WARN_ON((OA_BUFFER_SIZE - head) < report_size)) {
			DRM_ERROR("Spurious OA head ptr: non-integral report offset\n");
			break;
		}

		/* The report-ID field for periodic samples includes
		 * some undocumented flags related to what triggered
		 * the report and is never expected to be zero so we
		 * can check that the report isn't invalid before
		 * copying it to userspace...
		 */
		if (report32[0] == 0) {
			if (printk_ratelimit())
				DRM_NOTE("Skipping spurious, invalid OA report\n");
			continue;
		}

		/* Report timestamp should not exceed the given ts */
		if (report32[1] > ts)
			break;

		ret = append_oa_buffer_sample(stream, buf, count, offset, report);
		if (ret)
			break;

		report_count++;
		/* The above report-id field sanity check is based on
		 * the assumption that the OA buffer is initially
		 * zeroed and we reset the field after copying so the
		 * check is still meaningful once old reports start
		 * being overwritten.
		 */
		report32[0] = 0;
	}


	if (start_offset != *offset) {
		spin_lock_irqsave(&dev_priv->perf.oa.oa_buffer.ptr_lock, flags);

		/* We removed the gtt_offset for the copy loop above, indexing
		 * relative to oa_buf_base so put back here...
		 */
		head += gtt_offset;

		I915_WRITE(GEN7_OASTATUS2,
			   ((head & GEN7_OASTATUS2_HEAD_MASK) |
			    OA_MEM_SELECT_GGTT));
		dev_priv->perf.oa.oa_buffer.head = head;

		spin_unlock_irqrestore(&dev_priv->perf.oa.oa_buffer.ptr_lock, flags);
	}

	return ret;
}

/**
 * gen7_oa_read - copy status records then buffered OA reports
 * @stream: An i915-perf stream opened for OA metrics
 * @buf: destination buffer given by userspace
 * @count: the number of bytes userspace wants to read
 * @offset: (inout): the current position for writing into @buf
 * @ts: copy OA reports till this timestamp
 * @max_reports: max number of OA reports to copy
 *
 * Checks Gen 7 specific OA unit status registers and if necessary appends
 * corresponding status records for userspace (such as for a buffer full
 * condition) and then initiate appending any buffered OA reports.
 *
 * Updates @offset according to the number of bytes successfully copied into
 * the userspace buffer.
 *
 * Returns: zero on success or a negative error code
 */
static int gen7_oa_read(struct i915_perf_stream *stream,
			char __user *buf,
			size_t count,
			size_t *offset,
			u32 ts,
			u32 max_reports)
{
	struct drm_i915_private *dev_priv = stream->dev_priv;
	u32 oastatus1;
	int ret;

	if (WARN_ON(!dev_priv->perf.oa.oa_buffer.vaddr))
		return -EIO;

	oastatus1 = I915_READ(GEN7_OASTATUS1);

	/* XXX: On Haswell we don't have a safe way to clear oastatus1
	 * bits while the OA unit is enabled (while the tail pointer
	 * may be updated asynchronously) so we ignore status bits
	 * that have already been reported to userspace.
	 */
	oastatus1 &= ~dev_priv->perf.oa.gen7_latched_oastatus1;

	/* We treat OABUFFER_OVERFLOW as a significant error:
	 *
	 * - The status can be interpreted to mean that the buffer is
	 *   currently full (with a higher precedence than OA_TAKEN()
	 *   which will start to report a near-empty buffer after an
	 *   overflow) but it's awkward that we can't clear the status
	 *   on Haswell, so without a reset we won't be able to catch
	 *   the state again.
	 *
	 * - Since it also implies the HW has started overwriting old
	 *   reports it may also affect our sanity checks for invalid
	 *   reports when copying to userspace that assume new reports
	 *   are being written to cleared memory.
	 *
	 * - In the future we may want to introduce a flight recorder
	 *   mode where the driver will automatically maintain a safe
	 *   guard band between head/tail, avoiding this overflow
	 *   condition, but we avoid the added driver complexity for
	 *   now.
	 */
	if (unlikely(oastatus1 & GEN7_OASTATUS1_OABUFFER_OVERFLOW)) {
		ret = append_oa_status(stream, buf, count, offset,
				       DRM_I915_PERF_RECORD_OA_BUFFER_LOST);
		if (ret)
			return ret;

		DRM_DEBUG("OA buffer overflow (exponent = %d): force restart\n",
			  dev_priv->perf.oa.period_exponent);

		dev_priv->perf.oa.ops.oa_disable(dev_priv);
		dev_priv->perf.oa.ops.oa_enable(dev_priv);

		oastatus1 = I915_READ(GEN7_OASTATUS1);
	}

	if (unlikely(oastatus1 & GEN7_OASTATUS1_REPORT_LOST)) {
		ret = append_oa_status(stream, buf, count, offset,
				       DRM_I915_PERF_RECORD_OA_REPORT_LOST);
		if (ret)
			return ret;
		dev_priv->perf.oa.gen7_latched_oastatus1 |=
			GEN7_OASTATUS1_REPORT_LOST;
	}

	return gen7_append_oa_reports(stream, buf, count, offset, ts,
					max_reports);
}

/**
 * append_one_cs_sample - Copies single perf sample data associated with
 * GPU command stream, into userspace read() buffer.
 * @stream: An i915-perf stream opened for perf CS metrics
 * @buf: destination buffer given by userspace
 * @count: the number of bytes userspace wants to read
 * @offset: (inout): the current position for writing into @buf
 * @node: Sample data associated with perf metrics
 *
 * Returns: 0 on success, negative error code on failure.
 */
static int append_one_cs_sample(struct i915_perf_stream *stream,
				char __user *buf,
				size_t count,
				size_t *offset,
				struct i915_perf_cs_sample *node)
{
	struct drm_i915_private *dev_priv = stream->dev_priv;
	struct sample_data data = { 0 };
	enum intel_engine_id id = stream->engine;
	u32 sample_flags = stream->sample_flags;
	u64 gpu_ts = 0;
	int ret = 0;

	if (sample_flags & SAMPLE_OA_REPORT) {
		const u8 *report = dev_priv->perf.command_stream_buf[id].vaddr +
				   node->oa_offset;
		u32 sample_ts = *(u32 *)(report + 4);

		data.report = report;

		/* First, append the periodic OA samples having lower
		 * timestamp values
		 */
		ret = dev_priv->perf.oa.ops.read(stream, buf, count, offset,
						sample_ts, U32_MAX);
		if (ret)
			return ret;

		if (sample_flags & SAMPLE_TS)
			gpu_ts = get_gpu_ts_from_oa_report(dev_priv, report);
	}

	if (sample_flags & SAMPLE_OA_SOURCE_INFO)
		data.source = I915_PERF_OA_EVENT_SOURCE_RCS;

	if (sample_flags & SAMPLE_CTX_ID) {
		data.ctx_id = node->ctx_id;
		dev_priv->perf.last_cmd_stream_ctx_id = node->ctx_id;
	}

	if (sample_flags & SAMPLE_PID) {
		data.pid = node->pid;
		dev_priv->perf.last_pid = node->pid;
	}

	if (sample_flags & SAMPLE_TAG) {
		data.tag = node->tag;
		dev_priv->perf.last_tag = node->tag;
	}

	if (sample_flags & SAMPLE_TS) {
		/* If OA sampling is enabled, derive the ts from OA report.
		 * Else, forward the timestamp collected via command stream.
		 */
		if (!(sample_flags & SAMPLE_OA_REPORT))
			gpu_ts = *(u64 *)
				(dev_priv->perf.command_stream_buf[id].vaddr +
					node->ts_offset);
		data.ts = gpu_ts;
	}

	return append_sample(stream, buf, count, offset, &data);
}

/**
 * append_command_stream_samples: Copies all comand stream based perf samples
 * into userspace read() buffer.
 * @stream: An i915-perf stream opened for perf CS metrics
 * @buf: destination buffer given by userspace
 * @count: the number of bytes userspace wants to read
 * @offset: (inout): the current position for writing into @buf
 *
 * Notably any error condition resulting in a short read (-%ENOSPC or
 * -%EFAULT) will be returned even though one or more records may
 * have been successfully copied. In this case it's up to the caller
 * to decide if the error should be squashed before returning to
 * userspace.
 *
 * Returns: 0 on success, negative error code on failure.
 */
static int append_command_stream_samples(struct i915_perf_stream *stream,
				char __user *buf,
				size_t count,
				size_t *offset)
{
	struct drm_i915_private *dev_priv = stream->dev_priv;
	struct i915_perf_cs_sample *entry, *next;
	enum intel_engine_id id = stream->engine;
	LIST_HEAD(free_list);
	int ret = 0;
	u32 status = dev_priv->perf.command_stream_buf[id].status;

	if (unlikely(status & I915_PERF_CMD_STREAM_BUF_STATUS_OVERFLOW)) {
		ret = append_oa_status(stream, buf, count, offset,
				       DRM_I915_PERF_RECORD_OA_BUFFER_LOST);
		if (ret)
			return ret;

		dev_priv->perf.command_stream_buf[id].status &=
				~I915_PERF_CMD_STREAM_BUF_STATUS_OVERFLOW;
	}

	spin_lock(&dev_priv->perf.sample_lock[id]);
	if (list_empty(&dev_priv->perf.cs_samples[id])) {
		spin_unlock(&dev_priv->perf.sample_lock[id]);
		goto pending_periodic;
	}
	list_for_each_entry_safe(entry, next,
				 &dev_priv->perf.cs_samples[id], link) {
		if (!i915_gem_request_completed(entry->request))
			break;
		list_move_tail(&entry->link, &free_list);
	}
	spin_unlock(&dev_priv->perf.sample_lock[id]);

	if (list_empty(&free_list))
		goto pending_periodic;

	list_for_each_entry_safe(entry, next, &free_list, link) {
		ret = append_one_cs_sample(stream, buf, count, offset, entry);
		if (ret)
			break;

		list_del(&entry->link);
		i915_gem_request_put(entry->request);
		kfree(entry);
	}

	/* Don't discard remaining entries, keep them for next read */
	spin_lock(&dev_priv->perf.sample_lock[id]);
	list_splice(&free_list, &dev_priv->perf.cs_samples[id]);
	spin_unlock(&dev_priv->perf.sample_lock[id]);

	return ret;

pending_periodic:
	if (!((stream->sample_flags & SAMPLE_OA_REPORT) &&
			dev_priv->perf.oa.n_pending_periodic_samples))
		return 0;

	ret = dev_priv->perf.oa.ops.read(stream, buf, count, offset,
				dev_priv->perf.oa.pending_periodic_ts,
				dev_priv->perf.oa.n_pending_periodic_samples);
	dev_priv->perf.oa.n_pending_periodic_samples = 0;
	dev_priv->perf.oa.pending_periodic_ts = 0;
	return ret;
}

enum cs_buf_state {
	CS_BUF_EMPTY,
	CS_BUF_REQ_PENDING,
	CS_BUF_HAVE_DATA,
};

/*
 * command_stream_buf_state - Checks whether the command stream buffer
 * associated with the stream has data available.
 * @stream: An i915-perf stream opened for OA metrics
 *
 * Returns:
 * CS_BUF_HAVE_DATA	- if there is atleast one completed request
 * CS_BUF_REQ_PENDING	- there are requests pending, but no completed requests
 * CS_BUF_EMPTY		- no requests scheduled
 */
static enum cs_buf_state command_stream_buf_state(
				struct i915_perf_stream *stream)
{
	struct drm_i915_private *dev_priv = stream->dev_priv;
	enum intel_engine_id id = stream->engine;
	struct i915_perf_cs_sample *entry = NULL;
	struct drm_i915_gem_request *request = NULL;

	spin_lock(&dev_priv->perf.sample_lock[id]);
	entry = list_first_entry_or_null(&dev_priv->perf.cs_samples[id],
			struct i915_perf_cs_sample, link);
	if (entry)
		request = entry->request;
	spin_unlock(&dev_priv->perf.sample_lock[id]);

	if (!entry)
		return CS_BUF_EMPTY;
	else if (!i915_gem_request_completed(request))
		return CS_BUF_REQ_PENDING;
	else
		return CS_BUF_HAVE_DATA;
}

/**
 * stream_have_data_unlocked - Checks whether the stream has data available
 * @stream: An i915-perf stream opened for OA metrics
 *
 * Note: We can safely forward the periodic OA samples in the case we have no
 * pending CS samples, but we can't do so in the case we have pending CS
 * samples, since we don't know what the ordering between pending CS samples
 * and periodic samples will eventually be. If we have no pending CS sample,
 * it won't be possible for future pending CS sample to have timestamps
 * earlier than current periodic timestamp.
 */

static bool stream_have_data_unlocked(struct i915_perf_stream *stream)
{
	struct drm_i915_private *dev_priv = stream->dev_priv;
	enum cs_buf_state state = CS_BUF_EMPTY;
	u32 num_samples = 0, last_ts = 0;

	if (stream->sample_flags & SAMPLE_OA_REPORT) {
		dev_priv->perf.oa.n_pending_periodic_samples = 0;
		dev_priv->perf.oa.pending_periodic_ts = 0;
		num_samples = dev_priv->perf.oa.ops.oa_buffer_num_reports(
						dev_priv, &last_ts);
	} else if (stream->cs_mode)
		state = command_stream_buf_state(stream);

	switch (state) {
	case CS_BUF_EMPTY:
		if (stream->sample_flags & SAMPLE_OA_REPORT) {
			dev_priv->perf.oa.n_pending_periodic_samples =
							num_samples;
			dev_priv->perf.oa.pending_periodic_ts = last_ts;
			return (num_samples != 0);
		} else
			return false;

	case CS_BUF_HAVE_DATA:
		return true;

	case CS_BUF_REQ_PENDING:
		default:
		return false;
	}
	return false;
}

/**
 * i915_engine_stream_wait_unlocked - handles blocking IO until data available
 * @stream: An i915-perf stream opened for GPU metrics
 *
 * Called when userspace tries to read() from a blocking stream FD opened
 * for perf metrics. It waits until the hrtimer callback finds a non-empty
 * command stream buffer / OA buffer and wakes us.
 *
 * Note: it's acceptable to have this return with some false positives
 * since any subsequent read handling will return -EAGAIN if there isn't
 * really data ready for userspace yet.
 *
 * Returns: zero on success or a negative error code
 */
static int i915_engine_stream_wait_unlocked(struct i915_perf_stream *stream)
{
	struct drm_i915_private *dev_priv = stream->dev_priv;
	enum intel_engine_id id = stream->engine;

	/* We would wait indefinitely if periodic sampling is not enabled */
	if (!dev_priv->perf.oa.periodic)
		return -EIO;

	if (stream->cs_mode) {
		int ret;

		/*
		 * Wait for the last submitted 'active' request.
		 */
		ret = i915_gem_active_wait(&stream->last_request,
					   I915_WAIT_INTERRUPTIBLE);
		if (ret) {
			DRM_ERROR("Failed to wait for stream active request\n");
			return ret;
		}
	}

	return wait_event_interruptible(dev_priv->perf.poll_wq[id],
					stream_have_data_unlocked(stream));
}

/**
 * i915_engine_stream_poll_wait - call poll_wait() for an stream poll()
 * @stream: An i915-perf stream opened for GPU metrics
 * @file: An i915 perf stream file
 * @wait: poll() state table
 *
 * For handling userspace polling on an i915 perf stream opened for metrics,
 * this starts a poll_wait with the wait queue that our hrtimer callback wakes
 * when it sees data ready to read either in command stream buffer or in the
 * circular OA buffer.
 */
static void i915_engine_stream_poll_wait(struct i915_perf_stream *stream,
			      struct file *file,
			      poll_table *wait)
{
	struct drm_i915_private *dev_priv = stream->dev_priv;

	poll_wait(file, &dev_priv->perf.poll_wq[stream->engine], wait);
}

/**
 * i915_engine_stream_read - Reads perf metrics available into userspace read
 * buffer
 * @stream: An i915-perf stream opened for GPU metrics
 * @buf: destination buffer given by userspace
 * @count: the number of bytes userspace wants to read
 * @offset: (inout): the current position for writing into @buf
 *
 * Updates @offset according to the number of bytes successfully copied into
 * the userspace buffer.
 *
 * Returns: zero on success or a negative error code
 */
static int i915_engine_stream_read(struct i915_perf_stream *stream,
			char __user *buf,
			size_t count,
			size_t *offset)
{
	struct drm_i915_private *dev_priv = stream->dev_priv;


	if (stream->cs_mode)
		return append_command_stream_samples(stream, buf, count,
							offset);
	else if (stream->sample_flags & SAMPLE_OA_REPORT)
		return dev_priv->perf.oa.ops.read(stream, buf, count, offset,
						U32_MAX, U32_MAX);
	else
		return -EINVAL;
}

/**
 * oa_get_render_ctx_id - determine and hold ctx hw id
 * @stream: An i915-perf stream opened for OA metrics
 *
 * Determine the render context hw id, and ensure it remains fixed for the
 * lifetime of the stream. This ensures that we don't have to worry about
 * updating the context ID in OACONTROL on the fly.
 *
 * Returns: zero on success or a negative error code
 */
static int oa_get_render_ctx_id(struct i915_perf_stream *stream)
{
	struct drm_i915_private *dev_priv = stream->dev_priv;

	if (i915.enable_execlists)
		dev_priv->perf.oa.specific_ctx_id = stream->ctx->hw_id;
	else {
		struct intel_engine_cs *engine = dev_priv->engine[RCS];
		int ret;

		ret = i915_mutex_lock_interruptible(&dev_priv->drm);
		if (ret)
			return ret;

		/* As the ID is the gtt offset of the context's vma we pin
		 * the vma to ensure the ID remains fixed.
		 */
		ret = engine->context_pin(engine, stream->ctx);
		if (ret) {
			mutex_unlock(&dev_priv->drm.struct_mutex);
			return ret;
		}

		/* Explicitly track the ID (instead of calling
		 * i915_ggtt_offset() on the fly) considering the difference
		 * with gen8+ and execlists
		 */
		dev_priv->perf.oa.specific_ctx_id =
			i915_ggtt_offset(stream->ctx->engine[engine->id].state);

		mutex_unlock(&dev_priv->drm.struct_mutex);
	}

	return 0;
}

/**
 * oa_put_render_ctx_id - counterpart to oa_get_render_ctx_id releases hold
 * @stream: An i915-perf stream opened for OA metrics
 *
 * In case anything needed doing to ensure the context HW ID would remain valid
 * for the lifetime of the stream, then that can be undone here.
 */
static void oa_put_render_ctx_id(struct i915_perf_stream *stream)
{
	struct drm_i915_private *dev_priv = stream->dev_priv;
	struct intel_engine_cs *engine = dev_priv->engine[RCS];

	if (i915.enable_execlists) {
		dev_priv->perf.oa.specific_ctx_id = INVALID_CTX_ID;
	} else {
		mutex_lock(&dev_priv->drm.struct_mutex);

		dev_priv->perf.oa.specific_ctx_id = INVALID_CTX_ID;
		engine->context_unpin(engine, stream->ctx);

		mutex_unlock(&dev_priv->drm.struct_mutex);
	}
}

static void
free_command_stream_buf(struct drm_i915_private *dev_priv,
			enum intel_engine_id id)
{
	mutex_lock(&dev_priv->drm.struct_mutex);

	i915_gem_object_unpin_map(
			dev_priv->perf.command_stream_buf[id].vma->obj);
	i915_vma_unpin(dev_priv->perf.command_stream_buf[id].vma);
	i915_gem_object_put(dev_priv->perf.command_stream_buf[id].vma->obj);

	dev_priv->perf.command_stream_buf[id].vma = NULL;
	dev_priv->perf.command_stream_buf[id].vaddr = NULL;

	mutex_unlock(&dev_priv->drm.struct_mutex);
}

static void
free_oa_buffer(struct drm_i915_private *i915)
{
	mutex_lock(&i915->drm.struct_mutex);

	i915_gem_object_unpin_map(i915->perf.oa.oa_buffer.vma->obj);
	i915_vma_unpin(i915->perf.oa.oa_buffer.vma);
	i915_gem_object_put(i915->perf.oa.oa_buffer.vma->obj);

	i915->perf.oa.oa_buffer.vma = NULL;
	i915->perf.oa.oa_buffer.vaddr = NULL;

	mutex_unlock(&i915->drm.struct_mutex);
}

static void i915_engine_stream_destroy(struct i915_perf_stream *stream)
{
	struct drm_i915_private *dev_priv = stream->dev_priv;

	if (WARN_ON(stream != dev_priv->perf.engine_stream[stream->engine]))
		return;

	if (stream->using_oa) {
		dev_priv->perf.oa.ops.disable_metric_set(dev_priv);

		free_oa_buffer(dev_priv);

		intel_uncore_forcewake_put(dev_priv, FORCEWAKE_ALL);
		intel_runtime_pm_put(dev_priv);

		if (stream->ctx)
			oa_put_render_ctx_id(stream);
	}

	if (stream->cs_mode)
		free_command_stream_buf(dev_priv, stream->engine);

	dev_priv->perf.engine_stream[stream->engine] = NULL;
}

static void gen7_init_oa_buffer(struct drm_i915_private *dev_priv)
{
	u32 gtt_offset = i915_ggtt_offset(dev_priv->perf.oa.oa_buffer.vma);
	unsigned long flags;

	spin_lock_irqsave(&dev_priv->perf.oa.oa_buffer.ptr_lock, flags);

	/* Pre-DevBDW: OABUFFER must be set with counters off,
	 * before OASTATUS1, but after OASTATUS2
	 */
	I915_WRITE(GEN7_OASTATUS2, gtt_offset | OA_MEM_SELECT_GGTT); /* head */
	dev_priv->perf.oa.oa_buffer.head = gtt_offset;

	I915_WRITE(GEN7_OABUFFER, gtt_offset);

	I915_WRITE(GEN7_OASTATUS1, gtt_offset | OABUFFER_SIZE_16M); /* tail */

	/* Mark that we need updated tail pointers to read from... */
	dev_priv->perf.oa.oa_buffer.tails[0].offset = INVALID_TAIL_PTR;
	dev_priv->perf.oa.oa_buffer.tails[1].offset = INVALID_TAIL_PTR;

	spin_unlock_irqrestore(&dev_priv->perf.oa.oa_buffer.ptr_lock, flags);

	/* On Haswell we have to track which OASTATUS1 flags we've
	 * already seen since they can't be cleared while periodic
	 * sampling is enabled.
	 */
	dev_priv->perf.oa.gen7_latched_oastatus1 = 0;

	/* NB: although the OA buffer will initially be allocated
	 * zeroed via shmfs (and so this memset is redundant when
	 * first allocating), we may re-init the OA buffer, either
	 * when re-enabling a stream or in error/reset paths.
	 *
	 * The reason we clear the buffer for each re-init is for the
	 * sanity check in gen7_append_oa_reports() that looks at the
	 * report-id field to make sure it's non-zero which relies on
	 * the assumption that new reports are being written to zeroed
	 * memory...
	 */
	memset(dev_priv->perf.oa.oa_buffer.vaddr, 0, OA_BUFFER_SIZE);

	/* Maybe make ->pollin per-stream state if we support multiple
	 * concurrent streams in the future.
	 */
	dev_priv->perf.pollin[RCS] = false;
}

static void gen8_init_oa_buffer(struct drm_i915_private *dev_priv)
{
	u32 gtt_offset = i915_ggtt_offset(dev_priv->perf.oa.oa_buffer.vma);
	unsigned long flags;

	spin_lock_irqsave(&dev_priv->perf.oa.oa_buffer.ptr_lock, flags);

	I915_WRITE(GEN8_OASTATUS, 0);
	I915_WRITE(GEN8_OAHEADPTR, gtt_offset);
	dev_priv->perf.oa.oa_buffer.head = gtt_offset;

	I915_WRITE(GEN8_OABUFFER_UDW, 0);

	/* PRM says:
	 *
	 *  "This MMIO must be set before the OATAILPTR
	 *  register and after the OAHEADPTR register. This is
	 *  to enable proper functionality of the overflow
	 *  bit."
	 */
	I915_WRITE(GEN8_OABUFFER, gtt_offset |
		   OABUFFER_SIZE_16M | OA_MEM_SELECT_GGTT);
	I915_WRITE(GEN8_OATAILPTR, gtt_offset & GEN8_OATAILPTR_MASK);

	/* Mark that we need updated tail pointers to read from... */
	dev_priv->perf.oa.oa_buffer.tails[0].offset = INVALID_TAIL_PTR;
	dev_priv->perf.oa.oa_buffer.tails[1].offset = INVALID_TAIL_PTR;

	spin_unlock_irqrestore(&dev_priv->perf.oa.oa_buffer.ptr_lock, flags);


	/* NB: although the OA buffer will initially be allocated
	 * zeroed via shmfs (and so this memset is redundant when
	 * first allocating), we may re-init the OA buffer, either
	 * when re-enabling a stream or in error/reset paths.
	 *
	 * The reason we clear the buffer for each re-init is for the
	 * sanity check in gen8_append_oa_reports() that looks at the
	 * reason field to make sure it's non-zero which relies on
	 * the assumption that new reports are being written to zeroed
	 * memory...
	 */
	memset(dev_priv->perf.oa.oa_buffer.vaddr, 0, OA_BUFFER_SIZE);

	/* Maybe make ->pollin per-stream state if we support multiple
	 * concurrent streams in the future.
	 */
	dev_priv->perf.pollin[RCS] = false;
}

static int alloc_obj(struct drm_i915_private *dev_priv,
		     struct i915_vma **vma, u8 **vaddr)
{
	struct drm_i915_gem_object *bo;
	int ret;

	intel_runtime_pm_get(dev_priv);

	ret = i915_mutex_lock_interruptible(&dev_priv->drm);
	if (ret)
		goto out;

	BUILD_BUG_ON_NOT_POWER_OF_2(OA_BUFFER_SIZE);
	BUILD_BUG_ON(OA_BUFFER_SIZE < SZ_128K || OA_BUFFER_SIZE > SZ_16M);

	bo = i915_gem_object_create(dev_priv, OA_BUFFER_SIZE);
	if (IS_ERR(bo)) {
		DRM_ERROR("Failed to allocate i915 perf obj\n");
		ret = PTR_ERR(bo);
		goto unlock;
	}

	ret = i915_gem_object_set_cache_level(bo, I915_CACHE_LLC);
	if (ret)
		goto err_unref;

	/* PreHSW required 512K alignment, HSW requires 16M */
	*vma = i915_gem_object_ggtt_pin(bo, NULL, 0, SZ_16M, 0);
	if (IS_ERR(*vma)) {
		ret = PTR_ERR(*vma);
		goto err_unref;
	}

	*vaddr = i915_gem_object_pin_map(bo, I915_MAP_WB);
	if (IS_ERR(*vaddr)) {
		ret = PTR_ERR(*vaddr);
		goto err_unpin;
	}

	goto unlock;

err_unpin:
	i915_vma_unpin(*vma);

err_unref:
	i915_gem_object_put(bo);

unlock:
	mutex_unlock(&dev_priv->drm.struct_mutex);
out:
	intel_runtime_pm_put(dev_priv);
	return ret;
}

static int alloc_oa_buffer(struct drm_i915_private *dev_priv)
{
	struct i915_vma *vma;
	u8 *vaddr;
	int ret;

	if (WARN_ON(dev_priv->perf.oa.oa_buffer.vma))
		return -ENODEV;

	ret = alloc_obj(dev_priv, &vma, &vaddr);
	if (ret)
		return ret;

	dev_priv->perf.oa.oa_buffer.vma = vma;
	dev_priv->perf.oa.oa_buffer.vaddr = vaddr;

	dev_priv->perf.oa.ops.init_oa_buffer(dev_priv);

	DRM_DEBUG_DRIVER("OA Buffer initialized, gtt offset = 0x%x, vaddr = %p",
			 i915_ggtt_offset(dev_priv->perf.oa.oa_buffer.vma),
			 dev_priv->perf.oa.oa_buffer.vaddr);
	return 0;
}

static int alloc_command_stream_buf(struct i915_perf_stream *stream)
{
	struct drm_i915_private *dev_priv = stream->dev_priv;
	enum intel_engine_id id = stream->engine;
	struct i915_vma *vma;
	u8 *vaddr;
	int ret;

	if (WARN_ON(dev_priv->perf.command_stream_buf[id].vma))
		return -ENODEV;

	ret = alloc_obj(dev_priv, &vma, &vaddr);
	if (ret)
		return ret;

	dev_priv->perf.command_stream_buf[id].vma = vma;
	dev_priv->perf.command_stream_buf[id].vaddr = vaddr;
	if (WARN_ON(!list_empty(&dev_priv->perf.cs_samples[id])))
		INIT_LIST_HEAD(&dev_priv->perf.cs_samples[id]);

	dev_priv->perf.pollin[id] = false;

	DRM_DEBUG_DRIVER(
		"command stream buf initialized, gtt offset = 0x%x, vaddr = %p",
		 i915_ggtt_offset(dev_priv->perf.command_stream_buf[id].vma),
		 dev_priv->perf.command_stream_buf[id].vaddr);

	return 0;
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

static int hsw_enable_metric_set(struct drm_i915_private *dev_priv)
{
	int ret = i915_oa_select_metric_set_hsw(dev_priv);

	if (ret)
		return ret;

	I915_WRITE(GDT_CHICKEN_BITS, (I915_READ(GDT_CHICKEN_BITS) |
				      GT_NOA_ENABLE));

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

	config_oa_regs(dev_priv, dev_priv->perf.oa.mux_regs,
		       dev_priv->perf.oa.mux_regs_len);

	/* It apparently takes a fairly long time for a new MUX
	 * configuration to be be applied after these register writes.
	 * This delay duration was derived empirically based on the
	 * render_basic config but hopefully it covers the maximum
	 * configuration latency.
	 *
	 * As a fallback, the checks in _append_oa_reports() to skip
	 * invalid OA reports do also seem to work to discard reports
	 * generated before this config has completed - albeit not
	 * silently.
	 *
	 * Unfortunately this is essentially a magic number, since we
	 * don't currently know of a reliable mechanism for predicting
	 * how long the MUX config will take to apply and besides
	 * seeing invalid reports we don't know of a reliable way to
	 * explicitly check that the MUX config has landed.
	 *
	 * It's even possible we've miss characterized the underlying
	 * problem - it just seems like the simplest explanation why
	 * a delay at this location would mitigate any invalid reports.
	 */
	usleep_range(15000, 20000);

	config_oa_regs(dev_priv, dev_priv->perf.oa.b_counter_regs,
		       dev_priv->perf.oa.b_counter_regs_len);

	return 0;
}

static void hsw_disable_metric_set(struct drm_i915_private *dev_priv)
{
	I915_WRITE(GEN6_UCGCTL1, (I915_READ(GEN6_UCGCTL1) &
				  ~GEN6_CSUNIT_CLOCK_GATE_DISABLE));
	I915_WRITE(GEN7_MISCCPCTL, (I915_READ(GEN7_MISCCPCTL) |
				    GEN7_DOP_CLOCK_GATE_ENABLE));

	I915_WRITE(GDT_CHICKEN_BITS, (I915_READ(GDT_CHICKEN_BITS) &
				      ~GT_NOA_ENABLE));
}

/* Manages updating the per-context aspects of the OA stream
 * configuration across all contexts.
 *
 * The awkward consideration here is that OACTXCONTROL controls the
 * exponent for periodic sampling which is primarily used for system
 * wide profiling where we'd like a consistent sampling period even in
 * the face of context switches.
 *
 * Our approach of updating the register state context (as opposed to
 * say using a workaround batch buffer) ensures that the hardware
 * won't automatically reload an out-of-date timer exponent even
 * transiently before a WA BB could be parsed.
 */
static int configure_all_contexts(struct drm_i915_private *dev_priv)
{
	struct i915_gem_context *ctx;
	int ret;

	ret = i915_mutex_lock_interruptible(&dev_priv->drm);
	if (ret)
		return ret;

	list_for_each_entry(ctx, &dev_priv->context_list, link) {
		int i;

		for (i = 0; i < I915_NUM_ENGINES; i++) {
			/* The actual update of the register state context
			 * will happen the next time this logical ring
			 * is submitted. (See i915_oa_update_reg_state()
			 * which hooks into execlists_update_context())
			 */
			atomic_set(&ctx->engine[i].oa_state_dirty, true);
		}
	}

	mutex_unlock(&dev_priv->drm.struct_mutex);

	/* Now update the current context.
	 *
	 * Note: Using MMIO to update per-context registers requires
	 * some extra care...
	 */
	ret = intel_uncore_begin_ctx_mmio(dev_priv);
	if (ret) {
		DRM_ERROR("Failed to bring RCS out of idle to update current ctx OA state");
		return ret;
	}

	I915_WRITE(GEN8_OACTXCONTROL, ((dev_priv->perf.oa.period_exponent <<
					GEN8_OA_TIMER_PERIOD_SHIFT) |
				      (dev_priv->perf.oa.periodic ?
				       GEN8_OA_TIMER_ENABLE : 0) |
				      GEN8_OA_COUNTER_RESUME));

	config_oa_regs(dev_priv, dev_priv->perf.oa.flex_regs,
			dev_priv->perf.oa.flex_regs_len);

	intel_uncore_end_ctx_mmio(dev_priv);

	return 0;
}

static int bdw_enable_metric_set(struct drm_i915_private *dev_priv)
{
	int ret = i915_oa_select_metric_set_bdw(dev_priv);

	if (ret)
		return ret;

	I915_WRITE(GDT_CHICKEN_BITS, 0xA0);
	config_oa_regs(dev_priv, dev_priv->perf.oa.mux_regs,
		       dev_priv->perf.oa.mux_regs_len);
	I915_WRITE(GDT_CHICKEN_BITS, 0x80);

	/* It takes a fairly long time for a new MUX configuration to
	 * be be applied after these register writes. This delay
	 * duration is take from Haswell (derived empirically based on
	 * the render_basic config) but hopefully it covers the
	 * maximum configuration latency on BDW too...
	 */
	usleep_range(15000, 20000);

	config_oa_regs(dev_priv, dev_priv->perf.oa.b_counter_regs,
		       dev_priv->perf.oa.b_counter_regs_len);

	configure_all_contexts(dev_priv);

	return 0;
}

static void bdw_disable_metric_set(struct drm_i915_private *dev_priv)
{
	/* NOP */
}

static int chv_enable_metric_set(struct drm_i915_private *dev_priv)
{
	int ret = i915_oa_select_metric_set_chv(dev_priv);

	if (ret)
		return ret;

	I915_WRITE(GDT_CHICKEN_BITS, 0xA0);
	config_oa_regs(dev_priv, dev_priv->perf.oa.mux_regs,
		       dev_priv->perf.oa.mux_regs_len);
	I915_WRITE(GDT_CHICKEN_BITS, 0x80);

	/* It takes a fairly long time for a new MUX configuration to
	 * be be applied after these register writes. This delay
	 * duration is take from Haswell (derived empirically based on
	 * the render_basic config) but hopefully it covers the
	 * maximum configuration latency on CHV too...
	 */
	usleep_range(15000, 20000);

	config_oa_regs(dev_priv, dev_priv->perf.oa.b_counter_regs,
		       dev_priv->perf.oa.b_counter_regs_len);

	configure_all_contexts(dev_priv);

	return 0;
}

static void chv_disable_metric_set(struct drm_i915_private *dev_priv)
{
	/* NOP */
}

static int skl_enable_metric_set(struct drm_i915_private *dev_priv)
{
	if (IS_SKL_GT2(dev_priv)) {
		int ret = i915_oa_select_metric_set_sklgt2(dev_priv);
		if (ret)
			return ret;
	} else if (IS_SKL_GT3(dev_priv)) {
		int ret = i915_oa_select_metric_set_sklgt3(dev_priv);
		if (ret)
			return ret;
	} else if (IS_SKL_GT4(dev_priv)) {
		int ret = i915_oa_select_metric_set_sklgt4(dev_priv);
		if (ret)
			return ret;
	} else
		return -ENOTSUPP;

	/* We disable slice/unslice clock ratio change reports on SKL since
	 * they are too noisy. The HW generates a lot redundant reports where
	 * the ratio hasn't really changed causing a lot of redundant work to
	 * processes and increasing the chances we'll hit buffer overruns.
	 *
	 * Although we don't currently use the 'disable overrun' OABUFFER
	 * feature it's worth noting that clock ratio reports have to be
	 * disabled before considering to use that feature since the HW doesn't
	 * correctly block these reports.
	 *
	 * Currently none of the high-level metrics we have depend on knowing
	 * this ratio to normalize.
	 *
	 * Note: This register is not power context saved and restored, but
	 * that's OK considering that we disable RC6 while the OA unit is
	 * enabled.
	 *
	 * The _INCLUDE_CLK_RATIO bit allows the slice/unslice frequency to
	 * be read back from automatically triggered reports, as part of the
	 * RPT_ID field.
	 */
	I915_WRITE(GEN8_OA_DEBUG,
		   _MASKED_BIT_ENABLE(GEN9_OA_DEBUG_DISABLE_CLK_RATIO_REPORTS |
				      GEN9_OA_DEBUG_INCLUDE_CLK_RATIO));

	I915_WRITE(GDT_CHICKEN_BITS, 0xA0);
	config_oa_regs(dev_priv, dev_priv->perf.oa.mux_regs,
		       dev_priv->perf.oa.mux_regs_len);
	I915_WRITE(GDT_CHICKEN_BITS, 0x80);

	/* It takes a fairly long time for a new MUX configuration to
	 * be be applied after these register writes. This delay
	 * duration is take from Haswell (derived empirically based on
	 * the render_basic config) but hopefully it covers the
	 * maximum configuration latency on CHV too...
	 */
	usleep_range(15000, 20000);

	config_oa_regs(dev_priv, dev_priv->perf.oa.b_counter_regs,
		       dev_priv->perf.oa.b_counter_regs_len);

	configure_all_contexts(dev_priv);

	return 0;
}

static void skl_disable_metric_set(struct drm_i915_private *dev_priv)
{
	/* NOP */
}

static int bxt_enable_metric_set(struct drm_i915_private *dev_priv)
{
	int ret = i915_oa_select_metric_set_bxt(dev_priv);

	if (ret)
		return ret;

	/* We disable slice/unslice clock ratio change reports on SKL since
	 * they are too noisy. The HW generates a lot redundant reports where
	 * the ratio hasn't really changed causing a lot of redundant work to
	 * processes and increasing the chances we'll hit buffer overruns.
	 *
	 * Although we don't currently use the 'disable overrun' OABUFFER
	 * feature it's worth noting that clock ratio reports have to be
	 * disabled before considering to use that feature since the HW doesn't
	 * correctly block these reports.
	 *
	 * Currently none of the high-level metrics we have depend on knowing
	 * this ratio to normalize.
	 *
	 * Note: This register is not power context saved and restored, but
	 * that's OK considering that we disable RC6 while the OA unit is
	 * enabled.
	 *
	 * The _INCLUDE_CLK_RATIO bit allows the slice/unslice frequency to
	 * be read back from automatically triggered reports, as part of the
	 * RPT_ID field.
	 */
	I915_WRITE(GEN8_OA_DEBUG,
		   _MASKED_BIT_ENABLE(GEN9_OA_DEBUG_DISABLE_CLK_RATIO_REPORTS |
				      GEN9_OA_DEBUG_INCLUDE_CLK_RATIO));

	I915_WRITE(GDT_CHICKEN_BITS, 0xA0);
	config_oa_regs(dev_priv, dev_priv->perf.oa.mux_regs,
		       dev_priv->perf.oa.mux_regs_len);
	I915_WRITE(GDT_CHICKEN_BITS, 0x80);

	/* It takes a fairly long time for a new MUX configuration to
	 * be be applied after these register writes. This delay
	 * duration is take from Haswell (derived empirically based on
	 * the render_basic config) but hopefully it covers the
	 * maximum configuration latency on CHV too...
	 */
	usleep_range(15000, 20000);

	config_oa_regs(dev_priv, dev_priv->perf.oa.b_counter_regs,
		       dev_priv->perf.oa.b_counter_regs_len);

	configure_all_contexts(dev_priv);

	return 0;
}

static void bxt_disable_metric_set(struct drm_i915_private *dev_priv)
{
	/* NOP */
}

static void gen7_update_oacontrol_locked(struct drm_i915_private *dev_priv)
{
	assert_spin_locked(&dev_priv->perf.hook_lock);

	if (dev_priv->perf.engine_stream[RCS]->state !=
					I915_PERF_STREAM_DISABLED) {
		struct i915_gem_context *ctx =
			dev_priv->perf.engine_stream[RCS]->ctx;
		u32 ctx_id = dev_priv->perf.oa.specific_ctx_id;

		bool periodic = dev_priv->perf.oa.periodic;
		u32 period_exponent = dev_priv->perf.oa.period_exponent;
		u32 report_format = dev_priv->perf.oa.oa_buffer.format;

		I915_WRITE(GEN7_OACONTROL,
			   (ctx_id & GEN7_OACONTROL_CTX_MASK) |
			   (period_exponent <<
			    GEN7_OACONTROL_TIMER_PERIOD_SHIFT) |
			   (periodic ? GEN7_OACONTROL_TIMER_ENABLE : 0) |
			   (report_format << GEN7_OACONTROL_FORMAT_SHIFT) |
			   (ctx ? GEN7_OACONTROL_PER_CTX_ENABLE : 0) |
			   GEN7_OACONTROL_ENABLE);
	} else
		I915_WRITE(GEN7_OACONTROL, 0);
}

static void gen7_oa_enable(struct drm_i915_private *dev_priv)
{
	unsigned long flags;

	/* Reset buf pointers so we don't forward reports from before now.
	 *
	 * Think carefully if considering trying to avoid this, since it
	 * also ensures status flags and the buffer itself are cleared
	 * in error paths, and we have checks for invalid reports based
	 * on the assumption that certain fields are written to zeroed
	 * memory which this helps maintains.
	 */
	gen7_init_oa_buffer(dev_priv);

	spin_lock_irqsave(&dev_priv->perf.hook_lock, flags);
	gen7_update_oacontrol_locked(dev_priv);
	spin_unlock_irqrestore(&dev_priv->perf.hook_lock, flags);
}

static void gen8_oa_enable(struct drm_i915_private *dev_priv)
{
	u32 report_format = dev_priv->perf.oa.oa_buffer.format;

	/* Reset buf pointers so we don't forward reports from before now.
	 *
	 * Think carefully if considering trying to avoid this, since it
	 * also ensures status flags and the buffer itself are cleared
	 * in error paths, and we have checks for invalid reports based
	 * on the assumption that certain fields are written to zeroed
	 * memory which this helps maintains.
	 */
	gen8_init_oa_buffer(dev_priv);

	/* Note: we don't rely on the hardware to perform single context
	 * filtering and instead filter on the cpu based on the context-id
	 * field of reports
	 */
	I915_WRITE(GEN8_OACONTROL, (report_format <<
				    GEN8_OA_REPORT_FORMAT_SHIFT) |
				   GEN8_OA_COUNTER_ENABLE);
}

/**
 * i915_engine_stream_enable - handle `I915_PERF_IOCTL_ENABLE` for perf stream
 * @stream: An i915 perf stream opened for GPU metrics
 *
 * [Re]enables hardware periodic sampling according to the period configured
 * when opening the stream. This also starts a hrtimer that will periodically
 * check for data in the circular OA buffer for notifying userspace (e.g.
 * during a read() or poll()).
 */
static void i915_engine_stream_enable(struct i915_perf_stream *stream)
{
	struct drm_i915_private *dev_priv = stream->dev_priv;

	if (stream->sample_flags & SAMPLE_OA_REPORT) {
		dev_priv->perf.oa.ops.oa_enable(dev_priv);

		if (stream->sample_flags & SAMPLE_TS)
			dev_priv->perf.oa.last_gpu_ts =
				I915_READ64_2x32(GT_TIMESTAMP_COUNT,
					GT_TIMESTAMP_COUNT_UDW);
	}

	if (stream->cs_mode || dev_priv->perf.oa.periodic)
		hrtimer_start(&dev_priv->perf.poll_check_timer,
			      ns_to_ktime(POLL_PERIOD),
			      HRTIMER_MODE_REL_PINNED);
}

static void gen7_oa_disable(struct drm_i915_private *dev_priv)
{
	I915_WRITE(GEN7_OACONTROL, 0);
}

static void gen8_oa_disable(struct drm_i915_private *dev_priv)
{
	I915_WRITE(GEN8_OACONTROL, 0);
}

/**
 * i915_engine_stream_disable - handle `I915_PERF_IOCTL_DISABLE` for perf stream
 * @stream: An i915 perf stream opened for GPU metrics
 *
 * Stops the OA unit from periodically writing counter reports into the
 * circular OA buffer. This also stops the hrtimer that periodically checks for
 * data in the circular OA buffer, for notifying userspace.
 */
static void i915_engine_stream_disable(struct i915_perf_stream *stream)
{
	struct drm_i915_private *dev_priv = stream->dev_priv;

	if (stream->cs_mode || dev_priv->perf.oa.periodic)
		hrtimer_cancel(&dev_priv->perf.poll_check_timer);

	if (stream->cs_mode) {
		/*
		 * Wait for the last submitted 'active' request, before freeing
		 * the requests associated with the stream.
		 */
		i915_gem_active_wait(&stream->last_request,
					   I915_WAIT_INTERRUPTIBLE);
		i915_engine_stream_release_samples(stream);
	}

	if (stream->sample_flags & SAMPLE_OA_REPORT)
		dev_priv->perf.oa.ops.oa_disable(dev_priv);
}

static const struct i915_perf_stream_ops i915_engine_stream_ops = {
	.destroy = i915_engine_stream_destroy,
	.enable = i915_engine_stream_enable,
	.disable = i915_engine_stream_disable,
	.wait_unlocked = i915_engine_stream_wait_unlocked,
	.poll_wait = i915_engine_stream_poll_wait,
	.read = i915_engine_stream_read,
	.command_stream_hook = i915_engine_stream_capture_cs_data,
};

/**
 * i915_engine_stream_init - validate combined props for stream and init
 * @stream: An i915 perf stream
 * @param: The open parameters passed to `DRM_I915_PERF_OPEN`
 * @props: The property state that configures stream (individually validated)
 *
 * While read_properties_unlocked() validates properties in isolation it
 * doesn't ensure that the combination necessarily makes sense.
 *
 * At this point it has been determined that userspace wants a stream of
 * perf metrics, but still we need to further validate the combined
 * properties are OK.
 *
 * If the configuration makes sense then we can allocate memory for
 * a circular perf buffer and apply the requested metric set configuration.
 *
 * Returns: zero on success or a negative error code.
 */
static int i915_engine_stream_init(struct i915_perf_stream *stream,
			       struct drm_i915_perf_open_param *param,
			       struct perf_open_properties *props)
{
	struct drm_i915_private *dev_priv = stream->dev_priv;
	bool require_oa_unit = props->sample_flags & (SAMPLE_OA_REPORT |
						      SAMPLE_OA_SOURCE_INFO);
	bool require_cs_mode = props->sample_flags & (SAMPLE_PID |
						      SAMPLE_TAG);
	bool cs_sample_data = props->sample_flags & (SAMPLE_OA_REPORT |
							SAMPLE_TS);
	int ret;

	/* To avoid the complexity of having to accurately filter
	 * counter reports and marshal to the appropriate client
	 * we currently only allow exclusive access
	 */
	if (dev_priv->perf.engine_stream[props->engine]) {
		DRM_DEBUG("I915 perf stream : %d already in use\n",
				props->engine);
		return -EBUSY;
	}

	if ((props->sample_flags & SAMPLE_CTX_ID) && !props->cs_mode) {
		if (IS_HASWELL(dev_priv)) {
			DRM_ERROR(
				"On HSW, context ID sampling only supported via command stream");
			return -EINVAL;
		} else if (!i915.enable_execlists) {
			DRM_ERROR(
				"On Gen8+ without execlists, context ID sampling only supported via command stream");
			return -EINVAL;
		}
	}

	stream->sample_size = sizeof(struct drm_i915_perf_record_header);

	if (require_oa_unit) {
		int format_size;

		/* If the sysfs metrics/ directory wasn't registered for some
		 * reason then don't let userspace try their luck with config
		 * IDs
		 */
		if (!dev_priv->perf.metrics_kobj) {
			DRM_DEBUG("OA metrics weren't advertised via sysfs\n");
			return -EINVAL;
		}

		if (!dev_priv->perf.oa.ops.init_oa_buffer) {
			DRM_DEBUG("OA unit not supported\n");
			return -ENODEV;
		}

		if (!props->metrics_set) {
			DRM_DEBUG("OA metric set not specified\n");
			return -EINVAL;
		}

		if (!props->oa_format) {
			DRM_DEBUG("OA report format not specified\n");
			return -EINVAL;
		}

		if (props->cs_mode  && (props->engine!= RCS)) {
			DRM_ERROR(
				  "Command stream OA metrics only available via Render CS\n");
			return -EINVAL;
		}
		stream->engine= RCS;
		stream->using_oa = true;

		format_size =
			dev_priv->perf.oa.oa_formats[props->oa_format].size;

		if (props->sample_flags & SAMPLE_OA_REPORT) {
			stream->sample_flags |= SAMPLE_OA_REPORT;
			stream->sample_size += format_size;
		}

		if (props->sample_flags & SAMPLE_OA_SOURCE_INFO) {
			if (!(props->sample_flags & SAMPLE_OA_REPORT)) {
				DRM_ERROR(
					  "OA source type can't be sampled without OA report");
				return -EINVAL;
			}
			stream->sample_flags |= SAMPLE_OA_SOURCE_INFO;
			stream->sample_size += 4;
		}

		dev_priv->perf.oa.oa_buffer.format_size = format_size;
		if (WARN_ON(dev_priv->perf.oa.oa_buffer.format_size == 0))
			return -EINVAL;

		dev_priv->perf.oa.oa_buffer.format =
			dev_priv->perf.oa.oa_formats[props->oa_format].format;

		dev_priv->perf.oa.metrics_set = props->metrics_set;

		dev_priv->perf.oa.periodic = props->oa_periodic;
		if (dev_priv->perf.oa.periodic)
			dev_priv->perf.oa.period_exponent = props->oa_period_exponent;

		if (stream->ctx) {
			ret = oa_get_render_ctx_id(stream);
			if (ret)
				return ret;
		}

		ret = alloc_oa_buffer(dev_priv);
		if (ret)
			goto err_oa_buf_alloc;

		/* PRM - observability performance counters:
		 *
		 *   OACONTROL, performance counter enable, note:
		 *
		 *   "When this bit is set, in order to have coherent counts,
		 *   RC6 power state and trunk clock gating must be disabled.
		 *   This can be achieved by programming MMIO registers as
		 *   0xA094=0 and 0xA090[31]=1"
		 *
		 *   In our case we are expecting that taking pm + FORCEWAKE
		 *   references will effectively disable RC6.
		 */
		intel_runtime_pm_get(dev_priv);
		intel_uncore_forcewake_get(dev_priv, FORCEWAKE_ALL);

		ret = dev_priv->perf.oa.ops.enable_metric_set(dev_priv);
		if (ret)
			goto err_enable;

	}

	if (props->sample_flags & SAMPLE_CTX_ID) {
		stream->sample_flags |= SAMPLE_CTX_ID;
		stream->sample_size += 4;

		/*
		 * NB: it's meaningful to request SAMPLE_CTX_ID with just CS
		 * mode or periodic OA mode sampling but we don't allow
		 * SAMPLE_CTX_ID without either mode
		 */
		if (!require_oa_unit)
			require_cs_mode = true;
	}

	if (props->sample_flags & SAMPLE_TS) {
		stream->sample_flags |= SAMPLE_TS;
		stream->sample_size += I915_PERF_TS_SAMPLE_SIZE;

		/*
		 * NB: it's meaningful to request SAMPLE_TS with just CS
		 * mode or periodic OA mode sampling but we don't allow
		 * SAMPLE_TS without either mode
		 */
		if (!require_oa_unit)
			require_cs_mode = true;
	}

	if (require_cs_mode && !props->cs_mode) {
		DRM_ERROR("PID/TAG/TS sampling requires engine to be specified");
		ret = -EINVAL;
		goto err_enable;
	}

	if (props->cs_mode) {
		if (!cs_sample_data) {
			DRM_ERROR(
				"Stream engine given without requesting any CS data to sample");
			ret = -EINVAL;
			goto err_enable;
		}

		/*
		 * The only time we should allow enabling CS mode if it's not
		 * strictly required, is if SAMPLE_CTX_ID/SAMPLE_TS has been
		 * requested as they're usable with periodic OA or CS sampling.
		 */
		if (!require_cs_mode &&
		    !(props->sample_flags & (SAMPLE_CTX_ID | SAMPLE_TS))) {
			DRM_ERROR(
				"Stream engine given without requesting any CS specific property");
			ret = -EINVAL;
			goto err_enable;
		}
		stream->cs_mode = true;
		stream->engine = props->engine;

		if (props->sample_flags & SAMPLE_PID) {
			stream->sample_flags |= SAMPLE_PID;
			stream->sample_size += 4;
		}

		if (props->sample_flags & SAMPLE_TAG) {
			stream->sample_flags |= SAMPLE_TAG;
			stream->sample_size += 4;
		}

		ret = alloc_command_stream_buf(stream);
		if (ret)
			goto err_enable;

		init_request_active(&stream->last_request, NULL);
	}

	stream->ops = &i915_engine_stream_ops;
	dev_priv->perf.engine_stream[stream->engine] = stream;

	return 0;

err_enable:
	if (require_oa_unit) {
		intel_uncore_forcewake_put(dev_priv, FORCEWAKE_ALL);
		intel_runtime_pm_put(dev_priv);
		free_oa_buffer(dev_priv);
	}

err_oa_buf_alloc:
	if (stream->ctx)
		oa_put_render_ctx_id(stream);

	return ret;
}

static void gen8_update_reg_state_unlocked(struct intel_engine_cs *engine,
					   struct i915_gem_context *ctx,
					   uint32_t *reg_state)
{
	struct drm_i915_private *dev_priv = ctx->i915;
	const struct i915_oa_reg *flex_regs = dev_priv->perf.oa.flex_regs;
	int n_flex_regs = dev_priv->perf.oa.flex_regs_len;
	int ctx_oactxctrl = dev_priv->perf.oa.ctx_oactxctrl_off;
	int ctx_flexeu0 = dev_priv->perf.oa.ctx_flexeu0_off;
	int i;

	reg_state[ctx_oactxctrl] = i915_mmio_reg_offset(GEN8_OACTXCONTROL);
	reg_state[ctx_oactxctrl+1] = (dev_priv->perf.oa.period_exponent <<
				      GEN8_OA_TIMER_PERIOD_SHIFT) |
				     (dev_priv->perf.oa.periodic ?
				      GEN8_OA_TIMER_ENABLE : 0) |
				     GEN8_OA_COUNTER_RESUME;

	for (i = 0; i < n_flex_regs; i++) {
		uint32_t offset = i915_mmio_reg_offset(flex_regs[i].addr);

		/* Map from mmio address to register state context
		 * offset...
		 */

		offset -= i915_mmio_reg_offset(EU_PERF_CNTL0);

		/* Flex EU mmio registers are separated by 256 bytes */
		offset /= 256;

		/* This offset is in dwords not bytes */
		offset *= 2;

		/* EU_PERF_CNTL0 offset in register state context... */
		offset += ctx_flexeu0;

		reg_state[offset] = i915_mmio_reg_offset(flex_regs[i].addr);
		reg_state[offset+1] = flex_regs[i].value;
	}

	atomic_set(&ctx->engine[engine->id].oa_state_dirty, false);
}

void i915_oa_update_reg_state(struct intel_engine_cs *engine,
			      struct i915_gem_context *ctx,
			      uint32_t *reg_state)
{
	struct drm_i915_private *dev_priv = engine->i915;

	if (!dev_priv->perf.initialized)
		return;

	/* XXX: We don't take a lock here and this may run async with
	 * respect to stream methods. Notably we don't want to block
	 * context switches by long i915 perf read() operations.
	 *
	 * It's expect to always be safe to read the dev_priv->perf
	 * state needed here, and expected to be benign to redundantly
	 * update the state if the OA unit has been disabled since
	 * oa_state_dirty was last set.
	 */
	if (atomic_read(&ctx->engine[engine->id].oa_state_dirty))
		gen8_update_reg_state_unlocked(engine, ctx, reg_state);
}

void i915_oa_init_reg_state(struct intel_engine_cs *engine,
			    struct i915_gem_context *ctx,
			    uint32_t *reg_state)
{
	struct drm_i915_private *dev_priv = engine->i915;

	if (!dev_priv->perf.initialized)
		return;

	/* XXX: We don't take a lock here and this may run async with
	 * respect to stream methods. Notably we don't want to block
	 * context switches by long i915 perf read() operations.
	 *
	 * It's expect to always be safe to read the dev_priv->perf
	 * state needed here, and expected to be benign to redundantly
	 * update the state if the OA unit has been disabled since
	 * oa_state_dirty was last set.
	 */
	gen8_update_reg_state_unlocked(engine, ctx, reg_state);
}

/**
 * i915_perf_read_locked - &i915_perf_stream_ops->read with error normalisation
 * @stream: An i915 perf stream
 * @file: An i915 perf stream file
 * @buf: destination buffer given by userspace
 * @count: the number of bytes userspace wants to read
 * @ppos: (inout) file seek position (unused)
 *
 * Besides wrapping &i915_perf_stream_ops->read this provides a common place to
 * ensure that if we've successfully copied any data then reporting that takes
 * precedence over any internal error status, so the data isn't lost.
 *
 * For example ret will be -ENOSPC whenever there is more buffered data than
 * can be copied to userspace, but that's only interesting if we weren't able
 * to copy some data because it implies the userspace buffer is too small to
 * receive a single record (and we never split records).
 *
 * Another case with ret == -EFAULT is more of a grey area since it would seem
 * like bad form for userspace to ask us to overrun its buffer, but the user
 * knows best:
 *
 *   http://yarchive.net/comp/linux/partial_reads_writes.html
 *
 * Returns: The number of bytes copied or a negative error code on failure.
 */
static ssize_t i915_perf_read_locked(struct i915_perf_stream *stream,
				     struct file *file,
				     char __user *buf,
				     size_t count,
				     loff_t *ppos)
{
	/* Note we keep the offset (aka bytes read) separate from any
	 * error status so that the final check for whether we return
	 * the bytes read with a higher precedence than any error (see
	 * comment below) doesn't need to be handled/duplicated in
	 * stream->ops->read() implementations.
	 */
	size_t offset = 0;
	int ret = stream->ops->read(stream, buf, count, &offset);

	return offset ?: (ret ?: -EAGAIN);
}

/**
 * i915_perf_read - handles read() FOP for i915 perf stream FDs
 * @file: An i915 perf stream file
 * @buf: destination buffer given by userspace
 * @count: the number of bytes userspace wants to read
 * @ppos: (inout) file seek position (unused)
 *
 * The entry point for handling a read() on a stream file descriptor from
 * userspace. Most of the work is left to the i915_perf_read_locked() and
 * &i915_perf_stream_ops->read but to save having stream implementations (of
 * which we might have multiple later) we handle blocking read here.
 *
 * We can also consistently treat trying to read from a disabled stream
 * as an IO error so implementations can assume the stream is enabled
 * while reading.
 *
 * Returns: The number of bytes copied or a negative error code on failure.
 */
static ssize_t i915_perf_read(struct file *file,
			      char __user *buf,
			      size_t count,
			      loff_t *ppos)
{
	struct i915_perf_stream *stream = file->private_data;
	struct drm_i915_private *dev_priv = stream->dev_priv;
	ssize_t ret;

	/* To ensure it's handled consistently we simply treat all reads of a
	 * disabled stream as an error. In particular it might otherwise lead
	 * to a deadlock for blocking file descriptors...
	 */
	if (stream->state == I915_PERF_STREAM_DISABLED)
		return -EIO;

	if (!(file->f_flags & O_NONBLOCK)) {
		/* There's the small chance of false positives from
		 * stream->ops->wait_unlocked.
		 *
		 * E.g. with single context filtering since we only wait until
		 * oabuffer has >= 1 report we don't immediately know whether
		 * any reports really belong to the current context
		 */
		do {
			ret = stream->ops->wait_unlocked(stream);
			if (ret)
				return ret;

			mutex_lock(&dev_priv->perf.lock);
			ret = i915_perf_read_locked(stream, file,
						    buf, count, ppos);
			mutex_unlock(&dev_priv->perf.lock);
		} while (ret == -EAGAIN);
	} else {
		mutex_lock(&dev_priv->perf.lock);
		ret = i915_perf_read_locked(stream, file, buf, count, ppos);
		mutex_unlock(&dev_priv->perf.lock);
	}

	/* We allow the poll checking to sometimes report false positive POLLIN
	 * events where we might actually report EAGAIN on read() if there's
	 * not really any data available. In this situation though we don't
	 * want to enter a busy loop between poll() reporting a POLLIN event
	 * and read() returning -EAGAIN. Clearing the oa.pollin state here
	 * effectively ensures we back off until the next hrtimer callback
	 * before reporting another POLLIN event.
	 */
	if (ret >= 0 || ret == -EAGAIN) {
		/* Maybe make ->pollin per-stream state if we support multiple
		 * concurrent streams in the future.
		 */
		dev_priv->perf.pollin[stream->engine] = false;
	}

	return ret;
}

static void wake_up_perf_streams(void *data, async_cookie_t cookie)
{
	struct drm_i915_private *dev_priv = data;
	struct i915_perf_stream *stream;

	mutex_lock(&dev_priv->perf.streams_lock);
	list_for_each_entry(stream, &dev_priv->perf.streams, link) {
		if (stream_have_data_unlocked(stream)) {
			dev_priv->perf.pollin[stream->engine] = true;
			wake_up(&dev_priv->perf.poll_wq[stream->engine]);
		}
	}
	mutex_unlock(&dev_priv->perf.streams_lock);
}

static enum hrtimer_restart poll_check_timer_cb(struct hrtimer *hrtimer)
{
	struct drm_i915_private *dev_priv =
		container_of(hrtimer, typeof(*dev_priv),
			     perf.poll_check_timer);

	async_schedule(wake_up_perf_streams, dev_priv);

	hrtimer_forward_now(hrtimer, ns_to_ktime(POLL_PERIOD));

	return HRTIMER_RESTART;
}

/**
 * i915_perf_poll_locked - poll_wait() with a suitable wait queue for stream
 * @dev_priv: i915 device instance
 * @stream: An i915 perf stream
 * @file: An i915 perf stream file
 * @wait: poll() state table
 *
 * For handling userspace polling on an i915 perf stream, this calls through to
 * &i915_perf_stream_ops->poll_wait to call poll_wait() with a wait queue that
 * will be woken for new stream data.
 *
 * Note: The &drm_i915_private->perf.lock mutex has been taken to serialize
 * with any non-file-operation driver hooks.
 *
 * Returns: any poll events that are ready without sleeping
 */
static unsigned int i915_perf_poll_locked(struct drm_i915_private *dev_priv,
					  struct i915_perf_stream *stream,
					  struct file *file,
					  poll_table *wait)
{
	unsigned int events = 0;

	stream->ops->poll_wait(stream, file, wait);

	/* Note: we don't explicitly check whether there's something to read
	 * here since this path may be very hot depending on what else
	 * userspace is polling, or on the timeout in use. We rely solely on
	 * the hrtimer/oa_poll_check_timer_cb to notify us when there are
	 * samples to read.
	 */
	if (dev_priv->perf.pollin[stream->engine])
		events |= POLLIN;

	return events;
}

/**
 * i915_perf_poll - call poll_wait() with a suitable wait queue for stream
 * @file: An i915 perf stream file
 * @wait: poll() state table
 *
 * For handling userspace polling on an i915 perf stream, this ensures
 * poll_wait() gets called with a wait queue that will be woken for new stream
 * data.
 *
 * Note: Implementation deferred to i915_perf_poll_locked()
 *
 * Returns: any poll events that are ready without sleeping
 */
static unsigned int i915_perf_poll(struct file *file, poll_table *wait)
{
	struct i915_perf_stream *stream = file->private_data;
	struct drm_i915_private *dev_priv = stream->dev_priv;
	int ret;

	mutex_lock(&dev_priv->perf.lock);
	ret = i915_perf_poll_locked(dev_priv, stream, file, wait);
	mutex_unlock(&dev_priv->perf.lock);

	return ret;
}

/**
 * i915_perf_enable_locked - handle `I915_PERF_IOCTL_ENABLE` ioctl
 * @stream: A disabled i915 perf stream
 *
 * [Re]enables the associated capture of data for this stream.
 *
 * If a stream was previously enabled then there's currently no intention
 * to provide userspace any guarantee about the preservation of previously
 * buffered data.
 */
static void i915_perf_enable_locked(struct i915_perf_stream *stream)
{
	if (stream->state != I915_PERF_STREAM_DISABLED)
		return;

	/* Allow stream->ops->enable() to refer to this */
	stream->state = I915_PERF_STREAM_ENABLE_IN_PROGRESS;

	if (stream->ops->enable)
		stream->ops->enable(stream);

	stream->state = I915_PERF_STREAM_ENABLED;
}

/**
 * i915_perf_disable_locked - handle `I915_PERF_IOCTL_DISABLE` ioctl
 * @stream: An enabled i915 perf stream
 *
 * Disables the associated capture of data for this stream.
 *
 * The intention is that disabling an re-enabling a stream will ideally be
 * cheaper than destroying and re-opening a stream with the same configuration,
 * though there are no formal guarantees about what state or buffered data
 * must be retained between disabling and re-enabling a stream.
 *
 * Note: while a stream is disabled it's considered an error for userspace
 * to attempt to read from the stream (-EIO).
 */
static void i915_perf_disable_locked(struct i915_perf_stream *stream)
{
	if (stream->state != I915_PERF_STREAM_ENABLED)
		return;

	/* Allow stream->ops->disable() to refer to this */
	stream->state = I915_PERF_STREAM_DISABLED;

	if (stream->ops->disable)
		stream->ops->disable(stream);
}

/**
 * i915_perf_ioctl - support ioctl() usage with i915 perf stream FDs
 * @stream: An i915 perf stream
 * @cmd: the ioctl request
 * @arg: the ioctl data
 *
 * Note: The &drm_i915_private->perf.lock mutex has been taken to serialize
 * with any non-file-operation driver hooks.
 *
 * Returns: zero on success or a negative error code. Returns -EINVAL for
 * an unknown ioctl request.
 */
static long i915_perf_ioctl_locked(struct i915_perf_stream *stream,
				   unsigned int cmd,
				   unsigned long arg)
{
	switch (cmd) {
	case I915_PERF_IOCTL_ENABLE:
		i915_perf_enable_locked(stream);
		return 0;
	case I915_PERF_IOCTL_DISABLE:
		i915_perf_disable_locked(stream);
		return 0;
	}

	return -EINVAL;
}

/**
 * i915_perf_ioctl - support ioctl() usage with i915 perf stream FDs
 * @file: An i915 perf stream file
 * @cmd: the ioctl request
 * @arg: the ioctl data
 *
 * Implementation deferred to i915_perf_ioctl_locked().
 *
 * Returns: zero on success or a negative error code. Returns -EINVAL for
 * an unknown ioctl request.
 */
static long i915_perf_ioctl(struct file *file,
			    unsigned int cmd,
			    unsigned long arg)
{
	struct i915_perf_stream *stream = file->private_data;
	struct drm_i915_private *dev_priv = stream->dev_priv;
	long ret;

	mutex_lock(&dev_priv->perf.lock);
	ret = i915_perf_ioctl_locked(stream, cmd, arg);
	mutex_unlock(&dev_priv->perf.lock);

	return ret;
}

/**
 * i915_perf_destroy_locked - destroy an i915 perf stream
 * @stream: An i915 perf stream
 *
 * Frees all resources associated with the given i915 perf @stream, disabling
 * any associated data capture in the process.
 *
 * Note: The &drm_i915_private->perf.lock mutex has been taken to serialize
 * with any non-file-operation driver hooks.
 */
static void i915_perf_destroy_locked(struct i915_perf_stream *stream)
{
	struct drm_i915_private *dev_priv = stream->dev_priv;

	mutex_lock(&dev_priv->perf.streams_lock);
	list_del(&stream->link);
	mutex_unlock(&dev_priv->perf.streams_lock);

	if (stream->state == I915_PERF_STREAM_ENABLED)
		i915_perf_disable_locked(stream);

	if (stream->ops->destroy)
		stream->ops->destroy(stream);

	if (stream->ctx)
		i915_gem_context_put_unlocked(stream->ctx);

	kfree(stream);
}

/**
 * i915_perf_release - handles userspace close() of a stream file
 * @inode: anonymous inode associated with file
 * @file: An i915 perf stream file
 *
 * Cleans up any resources associated with an open i915 perf stream file.
 *
 * NB: close() can't really fail from the userspace point of view.
 *
 * Returns: zero on success or a negative error code.
 */
static int i915_perf_release(struct inode *inode, struct file *file)
{
	struct i915_perf_stream *stream = file->private_data;
	struct drm_i915_private *dev_priv = stream->dev_priv;

	mutex_lock(&dev_priv->perf.lock);
	i915_perf_destroy_locked(stream);
	mutex_unlock(&dev_priv->perf.lock);

	return 0;
}


static const struct file_operations fops = {
	.owner		= THIS_MODULE,
	.llseek		= no_llseek,
	.release	= i915_perf_release,
	.poll		= i915_perf_poll,
	.read		= i915_perf_read,
	.unlocked_ioctl	= i915_perf_ioctl,
};


static struct i915_gem_context *
lookup_context(struct drm_i915_private *dev_priv,
	       struct drm_i915_file_private *file_priv,
	       u32 ctx_user_handle)
{
	struct i915_gem_context *ctx;
	int ret;

	ret = i915_mutex_lock_interruptible(&dev_priv->drm);
	if (ret)
		return ERR_PTR(ret);

	ctx = i915_gem_context_lookup(file_priv, ctx_user_handle);
	if (!IS_ERR(ctx))
		i915_gem_context_get(ctx);

	mutex_unlock(&dev_priv->drm.struct_mutex);

	return ctx;
}

/**
 * i915_perf_open_ioctl_locked - DRM ioctl() for userspace to open a stream FD
 * @dev_priv: i915 device instance
 * @param: The open parameters passed to 'DRM_I915_PERF_OPEN`
 * @props: individually validated u64 property value pairs
 * @file: drm file
 *
 * See i915_perf_ioctl_open() for interface details.
 *
 * Implements further stream config validation and stream initialization on
 * behalf of i915_perf_open_ioctl() with the &drm_i915_private->perf.lock mutex
 * taken to serialize with any non-file-operation driver hooks.
 *
 * Note: at this point the @props have only been validated in isolation and
 * it's still necessary to validate that the combination of properties makes
 * sense.
 *
 * In the case where userspace is interested in OA unit metrics then further
 * config validation and stream initialization details will be handled by
 * i915_oa_stream_init(). The code here should only validate config state that
 * will be relevant to all stream types / backends.
 *
 * Returns: zero on success or a negative error code.
 */
static int
i915_perf_open_ioctl_locked(struct drm_i915_private *dev_priv,
			    struct drm_i915_perf_open_param *param,
			    struct perf_open_properties *props,
			    struct drm_file *file)
{
	struct i915_gem_context *specific_ctx = NULL;
	struct i915_perf_stream *stream = NULL;
	unsigned long f_flags = 0;
	bool privileged_op = true;
	int stream_fd;
	int ret;

	if (props->single_context) {
		u32 ctx_handle = props->ctx_handle;
		struct drm_i915_file_private *file_priv = file->driver_priv;

		specific_ctx = lookup_context(dev_priv, file_priv, ctx_handle);
		if (IS_ERR(specific_ctx)) {
			ret = PTR_ERR(specific_ctx);
			if (ret != -EINTR)
				DRM_DEBUG("Failed to look up context with ID %u for opening perf stream\n",
					  ctx_handle);
			goto err;
		}
	}

	/* On Haswell the OA unit supports clock gating off for a specific
	 * context and in this mode there's no visibility of metrics for the
	 * rest of the system, which we consider acceptable for a
	 * non-privileged client.
	 *
	 * For Gen8+ the OA unit no longer supports clock gating off for a
	 * specific context and the kernel can't securely stop the counters
	 * from updating as system-wide / global values. Even though we can
	 * filter reports based on the included context ID we can't block
	 * clients from seeing the raw / global counter values via
	 * MI_REPORT_PERF_COUNT commands and so consider it a privileged op to
	 * enable the OA unit by default.
	 */
	if (IS_HASWELL(dev_priv) && specific_ctx)
		privileged_op = false;

	/* Similar to perf's kernel.perf_paranoid_cpu sysctl option
	 * we check a dev.i915.perf_stream_paranoid sysctl option
	 * to determine if it's ok to access system wide OA counters
	 * without CAP_SYS_ADMIN privileges.
	 */
	if (privileged_op &&
	    i915_perf_stream_paranoid && !capable(CAP_SYS_ADMIN)) {
		DRM_DEBUG("Insufficient privileges to open system-wide i915 perf stream\n");
		ret = -EACCES;
		goto err_ctx;
	}

	stream = kzalloc(sizeof(*stream), GFP_KERNEL);
	if (!stream) {
		ret = -ENOMEM;
		goto err_ctx;
	}

	stream->dev_priv = dev_priv;
	stream->ctx = specific_ctx;

	ret = i915_engine_stream_init(stream, param, props);
	if (ret)
		goto err_alloc;

	/* we avoid simply assigning stream->sample_flags = props->sample_flags
	 * to have _stream_init check the combination of sample flags more
	 * thoroughly, but still this is the expected result at this point.
	 */
	if (WARN_ON(stream->sample_flags != props->sample_flags)) {
		ret = -ENODEV;
		goto err_alloc;
	}

	mutex_lock(&dev_priv->perf.streams_lock);
	list_add(&stream->link, &dev_priv->perf.streams);
	mutex_unlock(&dev_priv->perf.streams_lock);

	if (param->flags & I915_PERF_FLAG_FD_CLOEXEC)
		f_flags |= O_CLOEXEC;
	if (param->flags & I915_PERF_FLAG_FD_NONBLOCK)
		f_flags |= O_NONBLOCK;

	stream_fd = anon_inode_getfd("[i915_perf]", &fops, stream, f_flags);
	if (stream_fd < 0) {
		ret = stream_fd;
		goto err_open;
	}

	if (!(param->flags & I915_PERF_FLAG_DISABLED))
		i915_perf_enable_locked(stream);

	return stream_fd;

err_open:
	mutex_lock(&dev_priv->perf.streams_lock);
	list_del(&stream->link);
	mutex_unlock(&dev_priv->perf.streams_lock);
	if (stream->ops->destroy)
		stream->ops->destroy(stream);
err_alloc:
	kfree(stream);
err_ctx:
	if (specific_ctx)
		i915_gem_context_put_unlocked(specific_ctx);
err:
	return ret;
}

/**
 * read_properties_unlocked - validate + copy userspace stream open properties
 * @dev_priv: i915 device instance
 * @uprops: The array of u64 key value pairs given by userspace
 * @n_props: The number of key value pairs expected in @uprops
 * @props: The stream configuration built up while validating properties
 *
 * Note this function only validates properties in isolation it doesn't
 * validate that the combination of properties makes sense or that all
 * properties necessary for a particular kind of stream have been set.
 *
 * Note that there currently aren't any ordering requirements for properties so
 * we shouldn't validate or assume anything about ordering here. This doesn't
 * rule out defining new properties with ordering requirements in the future.
 */
static int read_properties_unlocked(struct drm_i915_private *dev_priv,
				    u64 __user *uprops,
				    u32 n_props,
				    struct perf_open_properties *props)
{
	u64 __user *uprop = uprops;
	int i;

	memset(props, 0, sizeof(struct perf_open_properties));

	if (!n_props) {
		DRM_DEBUG("No i915 perf properties given\n");
		return -EINVAL;
	}

	/* Considering that ID = 0 is reserved and assuming that we don't
	 * (currently) expect any configurations to ever specify duplicate
	 * values for a particular property ID then the last _PROP_MAX value is
	 * one greater than the maximum number of properties we expect to get
	 * from userspace.
	 */
	if (n_props >= DRM_I915_PERF_PROP_MAX) {
		DRM_DEBUG("More i915 perf properties specified than exist\n");
		return -EINVAL;
	}

	for (i = 0; i < n_props; i++) {
		u64 oa_period, oa_freq_hz;
		u64 id, value;
		int ret;

		ret = get_user(id, uprop);
		if (ret)
			return ret;

		ret = get_user(value, uprop + 1);
		if (ret)
			return ret;

		switch ((enum drm_i915_perf_property_id)id) {
		case DRM_I915_PERF_PROP_CTX_HANDLE:
			props->single_context = 1;
			props->ctx_handle = value;
			break;
		case DRM_I915_PERF_PROP_SAMPLE_OA:
			props->sample_flags |= SAMPLE_OA_REPORT;
			break;
		case DRM_I915_PERF_PROP_OA_METRICS_SET:
			if (value == 0 ||
			    value > dev_priv->perf.oa.n_builtin_sets) {
				DRM_DEBUG("Unknown OA metric set ID\n");
				return -EINVAL;
			}
			props->metrics_set = value;
			break;
		case DRM_I915_PERF_PROP_OA_FORMAT:
			if (value == 0 || value >= I915_OA_FORMAT_MAX) {
				DRM_DEBUG("Out-of-range OA report format %llu\n",
					  value);
				return -EINVAL;
			}
			if (!dev_priv->perf.oa.oa_formats[value].size) {
				DRM_DEBUG("Unsupported OA report format %llu\n",
					  value);
				return -EINVAL;
			}
			props->oa_format = value;
			break;
		case DRM_I915_PERF_PROP_OA_EXPONENT:
			if (value > OA_EXPONENT_MAX) {
				DRM_DEBUG("OA timer exponent too high (> %u)\n",
					 OA_EXPONENT_MAX);
				return -EINVAL;
			}

			/* Theoretically we can program the OA unit to sample
			 * every 160ns but don't allow that by default unless
			 * root.
			 *
			 * On Haswell the period is derived from the exponent
			 * as:
			 *
			 *   period = 80ns * 2^(exponent + 1)
			 */
			BUILD_BUG_ON(sizeof(oa_period) != 8);
			oa_period = 80ull * (2ull << value);

			/* This check is primarily to ensure that oa_period <=
			 * UINT32_MAX (before passing to do_div which only
			 * accepts a u32 denominator), but we can also skip
			 * checking anything < 1Hz which implicitly can't be
			 * limited via an integer oa_max_sample_rate.
			 */
			if (oa_period <= NSEC_PER_SEC) {
				u64 tmp = NSEC_PER_SEC;
				do_div(tmp, oa_period);
				oa_freq_hz = tmp;
			} else
				oa_freq_hz = 0;

			if (oa_freq_hz > i915_oa_max_sample_rate &&
			    !capable(CAP_SYS_ADMIN)) {
				DRM_DEBUG("OA exponent would exceed the max sampling frequency (sysctl dev.i915.oa_max_sample_rate) %uHz without root privileges\n",
					  i915_oa_max_sample_rate);
				return -EACCES;
			}

			props->oa_periodic = true;
			props->oa_period_exponent = value;
			break;
		case DRM_I915_PERF_PROP_SAMPLE_OA_SOURCE:
			props->sample_flags |= SAMPLE_OA_SOURCE_INFO;
			break;
		case DRM_I915_PERF_PROP_ENGINE: {
				unsigned int user_ring_id =
					value & I915_EXEC_RING_MASK;

				if (user_ring_id > I915_USER_RINGS)
					return -EINVAL;

				props->cs_mode = true;
				props->engine = user_ring_map[user_ring_id];
			}
			break;
		case DRM_I915_PERF_PROP_SAMPLE_CTX_ID:
			props->sample_flags |= SAMPLE_CTX_ID;
			break;
		case DRM_I915_PERF_PROP_SAMPLE_PID:
			props->sample_flags |= SAMPLE_PID;
			break;
		case DRM_I915_PERF_PROP_SAMPLE_TAG:
			props->sample_flags |= SAMPLE_TAG;
			break;
		case DRM_I915_PERF_PROP_SAMPLE_TS:
			props->sample_flags |= SAMPLE_TS;
			break;
		default:
			MISSING_CASE(id);
			DRM_DEBUG("Unknown i915 perf property ID\n");
			return -EINVAL;
		}

		uprop += 2;
	}

	return 0;
}

/**
 * i915_perf_open_ioctl - DRM ioctl() for userspace to open a stream FD
 * @dev: drm device
 * @data: ioctl data copied from userspace (unvalidated)
 * @file: drm file
 *
 * Validates the stream open parameters given by userspace including flags
 * and an array of u64 key, value pair properties.
 *
 * Very little is assumed up front about the nature of the stream being
 * opened (for instance we don't assume it's for periodic OA unit metrics). An
 * i915-perf stream is expected to be a suitable interface for other forms of
 * buffered data written by the GPU besides periodic OA metrics.
 *
 * Note we copy the properties from userspace outside of the i915 perf
 * mutex to avoid an awkward lockdep with mmap_sem.
 *
 * Most of the implementation details are handled by
 * i915_perf_open_ioctl_locked() after taking the &drm_i915_private->perf.lock
 * mutex for serializing with any non-file-operation driver hooks.
 *
 * Return: A newly opened i915 Perf stream file descriptor or negative
 * error code on failure.
 */
int i915_perf_open_ioctl(struct drm_device *dev, void *data,
			 struct drm_file *file)
{
	struct drm_i915_private *dev_priv = dev->dev_private;
	struct drm_i915_perf_open_param *param = data;
	struct perf_open_properties props;
	u32 known_open_flags;
	int ret;

	if (!dev_priv->perf.initialized) {
		DRM_DEBUG("i915 perf interface not available for this system\n");
		return -ENOTSUPP;
	}

	known_open_flags = I915_PERF_FLAG_FD_CLOEXEC |
			   I915_PERF_FLAG_FD_NONBLOCK |
			   I915_PERF_FLAG_DISABLED;
	if (param->flags & ~known_open_flags) {
		DRM_DEBUG("Unknown drm_i915_perf_open_param flag\n");
		return -EINVAL;
	}

	ret = read_properties_unlocked(dev_priv,
				       u64_to_user_ptr(param->properties_ptr),
				       param->num_properties,
				       &props);
	if (ret)
		return ret;

	mutex_lock(&dev_priv->perf.lock);
	ret = i915_perf_open_ioctl_locked(dev_priv, param, &props, file);
	mutex_unlock(&dev_priv->perf.lock);

	return ret;
}

/**
 * i915_perf_register - exposes i915-perf to userspace
 * @dev_priv: i915 device instance
 *
 * In particular OA metric sets are advertised under a sysfs metrics/
 * directory allowing userspace to enumerate valid IDs that can be
 * used to open an i915-perf stream.
 */
void i915_perf_register(struct drm_i915_private *dev_priv)
{
	if (!dev_priv->perf.initialized)
		return;

	/* To be sure we're synchronized with an attempted
	 * i915_perf_open_ioctl(); considering that we register after
	 * being exposed to userspace.
	 */
	mutex_lock(&dev_priv->perf.lock);

	dev_priv->perf.metrics_kobj =
		kobject_create_and_add("metrics",
				       &dev_priv->drm.primary->kdev->kobj);
	if (!dev_priv->perf.metrics_kobj)
		goto exit;

	if (IS_HASWELL(dev_priv)) {
		if (i915_perf_register_sysfs_hsw(dev_priv))
			goto sysfs_error;
	} else if (IS_BROADWELL(dev_priv)) {
		if (i915_perf_register_sysfs_bdw(dev_priv))
			goto sysfs_error;
	} else if (IS_CHERRYVIEW(dev_priv)) {
		if (i915_perf_register_sysfs_chv(dev_priv))
			goto sysfs_error;
	} else if (IS_SKYLAKE(dev_priv)) {
		if (IS_SKL_GT2(dev_priv)) {
			if (i915_perf_register_sysfs_sklgt2(dev_priv))
				goto sysfs_error;
		} else if (IS_SKL_GT3(dev_priv)) {
			if (i915_perf_register_sysfs_sklgt3(dev_priv))
				goto sysfs_error;
		} else if (IS_SKL_GT4(dev_priv)) {
			if (i915_perf_register_sysfs_sklgt4(dev_priv))
				goto sysfs_error;
		} else
			goto sysfs_error;
	} else if (IS_BROXTON(dev_priv)) {
		if (i915_perf_register_sysfs_bxt(dev_priv))
			goto sysfs_error;
	}

	goto exit;

sysfs_error:
	kobject_put(dev_priv->perf.metrics_kobj);
	dev_priv->perf.metrics_kobj = NULL;

exit:
	mutex_unlock(&dev_priv->perf.lock);
}

/**
 * i915_perf_unregister - hide i915-perf from userspace
 * @dev_priv: i915 device instance
 *
 * i915-perf state cleanup is split up into an 'unregister' and
 * 'deinit' phase where the interface is first hidden from
 * userspace by i915_perf_unregister() before cleaning up
 * remaining state in i915_perf_fini().
 */
void i915_perf_unregister(struct drm_i915_private *dev_priv)
{
	if (!dev_priv->perf.metrics_kobj)
		return;

        if (IS_HASWELL(dev_priv))
                i915_perf_unregister_sysfs_hsw(dev_priv);
        else if (IS_BROADWELL(dev_priv))
                i915_perf_unregister_sysfs_bdw(dev_priv);
        else if (IS_CHERRYVIEW(dev_priv))
                i915_perf_unregister_sysfs_chv(dev_priv);
        else if (IS_SKYLAKE(dev_priv)) {
		if (IS_SKL_GT2(dev_priv))
			i915_perf_unregister_sysfs_sklgt2(dev_priv);
		else if (IS_SKL_GT3(dev_priv))
			i915_perf_unregister_sysfs_sklgt3(dev_priv);
		else if (IS_SKL_GT4(dev_priv))
			i915_perf_unregister_sysfs_sklgt4(dev_priv);
	} else if (IS_BROXTON(dev_priv))
                i915_perf_unregister_sysfs_bxt(dev_priv);

	kobject_put(dev_priv->perf.metrics_kobj);
	dev_priv->perf.metrics_kobj = NULL;
}

static struct ctl_table oa_table[] = {
	{
	 .procname = "perf_stream_paranoid",
	 .data = &i915_perf_stream_paranoid,
	 .maxlen = sizeof(i915_perf_stream_paranoid),
	 .mode = 0644,
	 .proc_handler = proc_dointvec_minmax,
	 .extra1 = &zero,
	 .extra2 = &one,
	 },
	{
	 .procname = "oa_max_sample_rate",
	 .data = &i915_oa_max_sample_rate,
	 .maxlen = sizeof(i915_oa_max_sample_rate),
	 .mode = 0644,
	 .proc_handler = proc_dointvec_minmax,
	 .extra1 = &zero,
	 .extra2 = &oa_sample_rate_hard_limit,
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

/**
 * i915_perf_init - initialize i915-perf state on module load
 * @dev_priv: i915 device instance
 *
 * Initializes i915-perf state without exposing anything to userspace.
 *
 * Note: i915-perf initialization is split into an 'init' and 'register'
 * phase with the i915_perf_register() exposing state to userspace.
 */
void i915_perf_init(struct drm_i915_private *dev_priv)
{
	dev_priv->perf.oa.n_builtin_sets = 0;

	if (IS_HASWELL(dev_priv)) {
		dev_priv->perf.oa.ops.init_oa_buffer = gen7_init_oa_buffer;
		dev_priv->perf.oa.ops.enable_metric_set = hsw_enable_metric_set;
		dev_priv->perf.oa.ops.disable_metric_set = hsw_disable_metric_set;
		dev_priv->perf.oa.ops.oa_enable = gen7_oa_enable;
		dev_priv->perf.oa.ops.oa_disable = gen7_oa_disable;
		dev_priv->perf.oa.ops.read = gen7_oa_read;
		dev_priv->perf.oa.ops.oa_buffer_num_reports =
			gen7_oa_buffer_num_reports_unlocked;
		dev_priv->perf.oa.ops.get_ctx_id = gen7_oa_buffer_get_ctx_id;

		dev_priv->perf.oa.oa_formats = hsw_oa_formats;

		dev_priv->perf.oa.n_builtin_sets =
			i915_oa_n_builtin_metric_sets_hsw;
	} else if (i915.enable_execlists) {
		if (IS_BROADWELL(dev_priv)) {
			dev_priv->perf.oa.ops.enable_metric_set =
				bdw_enable_metric_set;
			dev_priv->perf.oa.ops.disable_metric_set =
				bdw_disable_metric_set;
			dev_priv->perf.oa.ctx_oactxctrl_off = 0x120;
			dev_priv->perf.oa.ctx_flexeu0_off = 0x2ce;
			dev_priv->perf.oa.gen8_valid_ctx_bit = (1<<25);
			dev_priv->perf.oa.n_builtin_sets =
				i915_oa_n_builtin_metric_sets_bdw;
		} else if (IS_CHERRYVIEW(dev_priv)) {
			dev_priv->perf.oa.ops.enable_metric_set =
				chv_enable_metric_set;
			dev_priv->perf.oa.ops.disable_metric_set =
				chv_disable_metric_set;
			dev_priv->perf.oa.ctx_oactxctrl_off = 0x120;
			dev_priv->perf.oa.ctx_flexeu0_off = 0x2ce;
			dev_priv->perf.oa.gen8_valid_ctx_bit = (1<<25);
			dev_priv->perf.oa.n_builtin_sets =
				i915_oa_n_builtin_metric_sets_chv;
		} else if (IS_SKYLAKE(dev_priv)) {
			dev_priv->perf.oa.ops.enable_metric_set =
				skl_enable_metric_set;
			dev_priv->perf.oa.ops.disable_metric_set =
				skl_disable_metric_set;
			dev_priv->perf.oa.ctx_oactxctrl_off = 0x128;
			dev_priv->perf.oa.ctx_flexeu0_off = 0x3de;
			dev_priv->perf.oa.gen8_valid_ctx_bit = (1<<16);


			if (IS_SKL_GT2(dev_priv)) {
				dev_priv->perf.oa.n_builtin_sets =
					i915_oa_n_builtin_metric_sets_sklgt2;
			} else if (IS_SKL_GT3(dev_priv)) {
				dev_priv->perf.oa.n_builtin_sets =
					i915_oa_n_builtin_metric_sets_sklgt3;
			} else if (IS_SKL_GT4(dev_priv)) {
				dev_priv->perf.oa.n_builtin_sets =
					i915_oa_n_builtin_metric_sets_sklgt4;
			}
		} else if (IS_BROXTON(dev_priv)) {
			dev_priv->perf.oa.ops.enable_metric_set =
				bxt_enable_metric_set;
			dev_priv->perf.oa.ops.disable_metric_set =
				bxt_disable_metric_set;
			dev_priv->perf.oa.ctx_oactxctrl_off = 0x128;
			dev_priv->perf.oa.ctx_flexeu0_off = 0x3de;
			dev_priv->perf.oa.gen8_valid_ctx_bit = (1<<16);
			dev_priv->perf.oa.n_builtin_sets =
				i915_oa_n_builtin_metric_sets_bxt;
		}

		if (dev_priv->perf.oa.n_builtin_sets) {
			dev_priv->perf.oa.ops.init_oa_buffer = gen8_init_oa_buffer;
			dev_priv->perf.oa.ops.oa_enable = gen8_oa_enable;
			dev_priv->perf.oa.ops.oa_disable = gen8_oa_disable;
			dev_priv->perf.oa.ops.read = gen8_oa_read;
			dev_priv->perf.oa.ops.oa_buffer_num_reports =
				gen8_oa_buffer_num_reports_unlocked;
		dev_priv->perf.oa.ops.get_ctx_id = gen8_oa_buffer_get_ctx_id;

			dev_priv->perf.oa.oa_formats = gen8_plus_oa_formats;
		}
	}

	if (dev_priv->perf.oa.n_builtin_sets) {
		int count;

		hrtimer_init(&dev_priv->perf.poll_check_timer,
				CLOCK_MONOTONIC, HRTIMER_MODE_REL);
		dev_priv->perf.poll_check_timer.function = poll_check_timer_cb;

		for (count = 0; count < I915_NUM_ENGINES; count++) {
			INIT_LIST_HEAD(&dev_priv->perf.cs_samples[count]);
			spin_lock_init(&dev_priv->perf.sample_lock[count]);
			init_waitqueue_head(&dev_priv->perf.poll_wq[count]);
		}

		INIT_LIST_HEAD(&dev_priv->perf.streams);
		mutex_init(&dev_priv->perf.lock);
		mutex_init(&dev_priv->perf.streams_lock);
		spin_lock_init(&dev_priv->perf.hook_lock);
		spin_lock_init(&dev_priv->perf.oa.oa_buffer.ptr_lock);

		dev_priv->perf.sysctl_header = register_sysctl_table(dev_root);

		dev_priv->perf.initialized = true;
	}
}

/**
 * i915_perf_fini - Counter part to i915_perf_init()
 * @dev_priv: i915 device instance
 */
void i915_perf_fini(struct drm_i915_private *dev_priv)
{
	if (!dev_priv->perf.initialized)
		return;

	unregister_sysctl_table(dev_priv->perf.sysctl_header);

	memset(&dev_priv->perf.oa.ops, 0, sizeof(dev_priv->perf.oa.ops));

	dev_priv->perf.initialized = false;
}
