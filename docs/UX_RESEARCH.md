# UX Research & Design Rationale: Triage Console

## Who this is for

A SOC (security operations center) analyst monitoring alerts during an
active shift — not a data scientist exploring historical trends, and not an
engineer debugging the pipeline itself. That distinction matters: this
person needs to make fast triage decisions ("is this real, does it need
escalation right now") under time pressure and alert fatigue, not perform
open-ended analysis.

## What decisions does this person need to make, and how fast?

1. **"Is there anything critical happening right now?"** — needs to be
   answerable in under 2 seconds, without reading any individual alert.
2. **"Which of these alerts deserves my attention first?"** — severity and
   recency both matter; a Critical alert from 30 seconds ago outranks a
   Medium alert from 5 minutes ago, but an analyst should be able to see
   both without navigating away from the current view.
3. **"What exactly happened, for this one alert?"** — once something looks
   worth investigating, the analyst needs full detail (source, destination,
   detector, rule, raw detail string) without losing their place in the
   overall alert list.

## Design iteration: v1 to v2

**v1 (rejected direction):** a flat, reverse-chronological table of all
alerts, one row each, no visual severity distinction beyond a text column.

**Why v1 fails this user:** during a real incident, alert volume spikes —
exactly when the analyst most needs to *not* read every row top to bottom.
A flat table buries the signal (a handful of Critical alerts) inside the
noise (many Medium/Low alerts), and forces linear scanning to find what
matters. This is a generic "list the data" answer, not a design decision
made for this specific user's actual task under pressure.

**v2 (implemented):** severity-first triage layout —
- A left-hand filter rail lets the analyst instantly narrow to just
  Critical, or just a specific detector, collapsing noise without losing
  the ability to see everything.
- Color-coded severity pills (red/orange/yellow/blue) exploit
  **pre-attentive processing** — the visual system detects color
  differences before conscious, sequential reading, so an analyst scanning
  the table can spot "there's a red one" without reading text at all. This
  is why severity is encoded as a colored pill in its own column rather
  than plain text, and why the timeline's lanes are also color-coded by
  the same scheme — consistent color-to-severity mapping across both views
  means the analyst doesn't have to re-learn the encoding when switching
  between them.
- A dedicated timeline strip above the table gives an at-a-glance answer
  to decision #1 ("is anything critical happening right now") — a cluster
  of red dots in the last minute is visible instantly, before reading any
  row.
- Clicking a row opens a **detail drawer** rather than navigating to a new
  page — this preserves decision #2's requirement: the analyst doesn't
  lose their place in the filtered list while inspecting one alert. This
  is **progressive disclosure**: summary information (time, severity, rule,
  source/destination) stays in the table at all times; full detail is one
  click away and dismissible without a page reload.

## Why a canvas timeline instead of a chart library

At genuinely high alert volumes (the stated production goal), rendering one
DOM element per alert in a scrolling list or a typical charting library's
default SVG-per-point approach becomes the actual bottleneck — the browser
has to lay out and paint thousands of individual elements. Drawing directly
to a `<canvas>` bitmap avoids that entirely: the timeline redraws as pixels,
not DOM nodes, so it stays responsive regardless of how many alerts are in
the visible window. This is a real engineering constraint driving a UI
decision, not an aesthetic choice — the same reasoning that motivates
purpose-built high-density libraries like uPlot in a larger production
build.

## Accessibility and quiet defaults

The color palette relies on hue *and* is paired with text labels
("Critical", "High", etc.) in both the pill and the timeline's lane labels
— color is reinforcing, not the only channel carrying the information, so
the interface remains usable for an analyst with color-vision deficiency.
The rest of the interface (typography, spacing, motion) is deliberately
quiet: a SOC analyst's cognitive budget during an incident should be spent
on the alerts, not on decorative UI competing for attention.
