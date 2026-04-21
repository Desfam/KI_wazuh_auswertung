import React, { useRef, useEffect } from 'react';

// Simple animated SVG liquid background inspired by Framer's AnimatedLiquidBackground
export function LiquidBackground() {
  const ref = useRef<SVGSVGElement>(null);
  useEffect(() => {
    let frame: number;
    let t = 0;
    const animate = () => {
      t += 0.015;
      if (ref.current) {
        // Animate 3 sine waves for a liquid effect
        const w = 1920, h = 400;
        const wave = (amp: number, freq: number, phase: number) =>
          Array.from({ length: w }, (_, x) =>
            h/2 + Math.sin((x / w) * Math.PI * 2 * freq + t + phase) * amp
          );
        const y1 = wave(32, 1.2, 0);
        const y2 = wave(18, 2.1, 1.2);
        const y3 = wave(10, 3.2, 2.4);
        const path = (y: number[], color: string, opacity: number) =>
          `<path d="M0,${y[0]} ` +
          y.map((v, x) => `L${x},${v}`).join(' ') +
          ` L${w},${h} L0,${h}Z" fill="${color}" fill-opacity="${opacity}"/>`;
        ref.current.innerHTML =
          path(y1, '#2d333b', 0.7) +
          path(y2, '#22272e', 0.6) +
          path(y3, '#444c56', 0.5);
      }
      frame = requestAnimationFrame(animate);
    };
    animate();
    return () => cancelAnimationFrame(frame);
  }, []);
  return (
    <svg
      ref={ref as any}
      width="100%"
      height="100%"
      viewBox="0 0 1920 400"
      style={{ position: 'absolute', inset: 0, width: '100vw', height: '100vh', zIndex: 0 }}
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
    />
  );
}
