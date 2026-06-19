'use client';

import { useEffect, useRef } from 'react';

// REAL WebGL2 particle scene. Loads the live engine from /public/scene.js,
// sourced verbatim from control_store *HOME*MOD*scene*js* (the same render the
// bar serves). Replaces the earlier 2D canvas placeholder. The script targets
// <canvas id="scene">, so it mounts onto the canvas below.
export default function Scene() {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const s = document.createElement('script');
    s.src = '/scene.js';
    s.async = true;
    document.body.appendChild(s);
    return () => {
      s.remove();
    };
  }, []);

  return <canvas id="scene" ref={ref} />;
}
