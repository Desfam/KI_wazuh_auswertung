import { useEffect, useRef } from 'react';

export function FluidWaves() {
  const svgRef = useRef<SVGSVGElement>(null);
  const animationRef = useRef<number>();
  const timeRef = useRef<number>(0);

  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;

    const animate = () => {
      timeRef.current += 0.015;

      // Wave 1 - Large, slow, red
      const wave1 = generateWavePath(
        0,
        timeRef.current * 0.5,
        0.4,
        40,
        1920,
        200
      );

      // Wave 2 - Medium, medium speed, pink
      const wave2 = generateWavePath(
        1,
        timeRef.current * 0.8,
        0.25,
        60,
        1920,
        200
      );

      // Wave 3 - Small, fast, cyan
      const wave3 = generateWavePath(
        2,
        timeRef.current * 1.1,
        0.15,
        80,
        1920,
        200
      );

      // Wave 4 - Tiny, very fast, orange
      const wave4 = generateWavePath(
        3,
        timeRef.current * 1.5,
        0.1,
        100,
        1920,
        200
      );

      // Update paths
      const paths = svg.querySelectorAll('path');
      if (paths[0]) paths[0].setAttribute('d', wave1);
      if (paths[1]) paths[1].setAttribute('d', wave2);
      if (paths[2]) paths[2].setAttribute('d', wave3);
      if (paths[3]) paths[3].setAttribute('d', wave4);

      animationRef.current = requestAnimationFrame(animate);
    };

    animationRef.current = requestAnimationFrame(animate);

    return () => {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
    };
  }, []);

  return (
    <svg
      ref={svgRef}
      width="100%"
      height="100%"
      viewBox="0 0 1920 1080"
      preserveAspectRatio="none"
      style={{
        position: 'absolute',
        top: 0,
        left: 0,
        width: '100%',
        height: '100%',
      }}
    >
      <defs>
        <linearGradient id="grad1" x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" style={{ stopColor: '#ff1744', stopOpacity: 0.8 }} />
          <stop offset="100%" style={{ stopColor: '#ff1744', stopOpacity: 0.3 }} />
        </linearGradient>
        <linearGradient id="grad2" x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" style={{ stopColor: '#ff006e', stopOpacity: 0.7 }} />
          <stop offset="100%" style={{ stopColor: '#ff006e', stopOpacity: 0.2 }} />
        </linearGradient>
        <linearGradient id="grad3" x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" style={{ stopColor: '#00e5ff', stopOpacity: 0.6 }} />
          <stop offset="100%" style={{ stopColor: '#00e5ff', stopOpacity: 0.15 }} />
        </linearGradient>
        <linearGradient id="grad4" x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" style={{ stopColor: '#ff9100', stopOpacity: 0.5 }} />
          <stop offset="100%" style={{ stopColor: '#ff9100', stopOpacity: 0.1 }} />
        </linearGradient>
      </defs>

      {/* Wave 1 */}
      <path fill="url(#grad1)" />
      {/* Wave 2 */}
      <path fill="url(#grad2)" />
      {/* Wave 3 */}
      <path fill="url(#grad3)" />
      {/* Wave 4 */}
      <path fill="url(#grad4)" />
    </svg>
  );
}

function generateWavePath(
  offsetY: number,
  time: number,
  amplitude: number,
  frequency: number,
  width: number,
  height: number
): string {
  let pathData = `M 0 ${offsetY * height + height * 0.3}`;

  // Generate wave points
  for (let x = 0; x <= width; x += 20) {
    const y =
      Math.sin((x / frequency + time) * (Math.PI / 180)) * amplitude * height +
      offsetY * height +
      height * 0.4;
    pathData += ` L ${x} ${y}`;
  }

  // Close path to create filled area
  pathData += ` L ${width} ${height} L 0 ${height} Z`;

  return pathData;
}
