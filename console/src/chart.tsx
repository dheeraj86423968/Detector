import { useLayoutEffect, useRef, useState } from "react";

/** Single-series daily bar chart (inline SVG): thin bars, recessive grid, per-bar hover tooltip. */
export function DailyBars({ data, unit, height = 168, color = "var(--accent)", tick = (v: number) => v.toLocaleString() }: { data: { date: string; value: number; partial?: boolean; future?: boolean }[]; unit: [string, string]; height?: number; color?: string; tick?: (v: number) => string }) {
  const [hover, setHover] = useState<number | null>(null);
  const box = useRef<HTMLDivElement>(null); const [W, setW] = useState(640);
  useLayoutEffect(() => {
    if (!box.current) return;
    const ro = new ResizeObserver(([e]) => setW(Math.max(200, Math.round(e.contentRect.width))));
    ro.observe(box.current); return () => ro.disconnect();
  }, []);
  const max = Math.max(1, ...data.map(d => d.value));
  const step = niceStep(max);
  const top = Math.ceil(max / step) * step;
  const ticks = Array.from({ length: Math.round(top / step) + 1 }, (_, i) => i * step);
  // room for the widest y label ("15.0 M") so it never wraps
  const H = height, padL = Math.max(32, 12 + 6.4 * Math.max(...ticks.map(t => tick(t).length))), padR = 6, padT = 10, padB = 24;
  const bw = (W - padL - padR) / Math.max(1, data.length);
  const barW = Math.min(bw * 0.6, 32);
  const y = (v: number) => padT + (H - padT - padB) * (1 - v / top);
  const day = (s: string) => new Date(s + "T12:00:00");
  const lab = (s: string) => day(s).toLocaleDateString(undefined, { day: "numeric", month: "short" });
  const h = hover != null ? data[hover] : null;
  return (
    <div className="chart" ref={box} onMouseLeave={() => setHover(null)}>
      <svg width={W} height={H} viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`${unit[1]} per day`}>
        {ticks.map(t => (
          <g key={t}>
            <line x1={padL} x2={W - padR} y1={y(t)} y2={y(t)} className={t === 0 ? "axis" : "grid"} />
          </g>
        ))}
        {data.map((d, i) => {
          const x = padL + i * bw;
          const bh = Math.max(0, y(0) - y(d.value));
          return (
            <g key={d.date} onMouseEnter={() => setHover(i)}>
              <rect x={x} y={padT} width={bw} height={H - padT - padB} fill="transparent" />
              {hover === i && <rect x={x + 1} y={padT} width={bw - 2} height={H - padT - padB} className="hoverband" />}
              {d.future ? <rect x={x + (bw - barW) / 2 + 0.5} y={y(0) - 14} width={barW - 1} height={13.5} rx={3} className="future" />
                : d.value > 0 && <path d={roundTop(x + (bw - barW) / 2, y(d.value), barW, bh, Math.min(3, bh))} fill={color} opacity={d.partial ? 0.55 : 1} />}
            </g>
          );
        })}
      </svg>
      <div className="chart-y" style={{ width: padL - 6 }}>
        {ticks.map(t => <span key={t} style={{ top: y(t) }}>{tick(t)}</span>)}
      </div>
      <div className="chart-x" style={{ paddingLeft: padL, paddingRight: padR }}>
        {data.map((d, i) => <span key={d.date}>{data.length <= 8 || i % 2 === (data.length - 1) % 2 ? lab(d.date) : ""}</span>)}
      </div>
      {h && hover != null && (
        <div className="chart-tip" style={{ left: padL + (hover + 0.5) * bw }}>
          <div className="chart-tip-date">{day(h.date).toLocaleDateString(undefined, { weekday: "short", day: "numeric", month: "short" })}</div>
          {h.future ? <div>Not recorded yet</div> : <div><b>{h.value.toLocaleString()}</b> {h.value === 1 ? unit[0] : unit[1]}{h.partial ? " so far" : ""}</div>}
        </div>
      )}
    </div>
  );
}

function niceStep(max: number) {
  const raw = max / 3;
  const p = Math.pow(10, Math.floor(Math.log10(Math.max(1, raw))));
  const m = raw / p;
  return Math.max(1, (m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10) * p);
}
function roundTop(x: number, y: number, w: number, h: number, r: number) {
  return `M${x},${y + h} L${x},${y + r} Q${x},${y} ${x + r},${y} L${x + w - r},${y} Q${x + w},${y} ${x + w},${y + r} L${x + w},${y + h} Z`;
}
