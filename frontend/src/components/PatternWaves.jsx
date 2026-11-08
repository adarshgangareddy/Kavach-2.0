import { useEffect, useRef, useState } from 'react'
import { useEffects } from './effects.jsx'

/**
 * PatternWaves: A subtle, lit halftone dot and silk wave animation for Kavach.
 * Generates an undulating, low-contrast wave pattern with a warm amber backlight.
 *
 * Performance and Accessibility:
 * - Stops animation loop when scrolled out of viewport via IntersectionObserver.
 * - Immediately renders static fallback when prefers-reduced-motion is active or effects are toggled off.
 * - Graceful fallback to static CSS if canvas context cannot be initialized.
 */
export default function PatternWaves({ className = '' }) {
  const containerRef = useRef(null)
  const canvasRef = useRef(null)
  const { motion } = useEffects()
  const [inView, setInView] = useState(true)

  // IntersectionObserver to pause rendering when out of viewport
  useEffect(() => {
    const el = containerRef.current
    if (!el || typeof IntersectionObserver === 'undefined') return

    const observer = new IntersectionObserver(
      ([entry]) => {
        setInView(entry.isIntersecting)
      },
      { threshold: 0.05 },
    )
    observer.observe(el)
    return () => observer.disconnect()
  }, [])

  // Animation Loop
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas || !motion || !inView) return

    const ctx = canvas.getContext('2d')
    if (!ctx) return

    let animId
    let width = (canvas.width = canvas.offsetWidth || 1200)
    let height = (canvas.height = canvas.offsetHeight || 600)

    function handleResize() {
      if (!canvas) return
      width = canvas.width = canvas.offsetWidth || 1200
      height = canvas.height = canvas.offsetHeight || 600
    }
    window.addEventListener('resize', handleResize)

    // Configuration for subtle, low-contrast draped silk halftone wave
    const spacing = 28
    const cols = Math.ceil(width / spacing) + 2
    const rows = Math.ceil(height / spacing) + 2

    let startTime = performance.now()

    function render(now) {
      const elapsed = (now - startTime) * 0.0007 // very slow, calm wave motion

      ctx.clearRect(0, 0, width, height)

      for (let r = 0; r < rows; r++) {
        for (let c = 0; c < cols; c++) {
          const x = c * spacing
          const y = r * spacing

          // Draped silk wave formula: superposition of slow sinusoidal waves
          const wave1 = Math.sin(x * 0.006 + elapsed) * 9
          const wave2 = Math.cos(y * 0.008 + elapsed * 0.8) * 8
          const wave3 = Math.sin((x + y) * 0.004 + elapsed * 0.6) * 6
          const waveTotal = wave1 + wave2 + wave3

          // Halftone lighting intensity: highlights shift across the grid
          const intensity = Math.sin(x * 0.004 + y * 0.005 + elapsed * 1.2) * 0.5 + 0.5
          const dotRadius = Math.max(0.6, 1.1 + intensity * 1.2)

          // Amber warm glow coloring with controlled low opacity
          // Behind hero text it stays ultra-subtle (alpha between 0.06 and 0.22)
          const alpha = 0.06 + intensity * 0.16

          ctx.beginPath()
          ctx.arc(x, y + waveTotal, dotRadius, 0, Math.PI * 2)
          ctx.fillStyle = `rgba(245, 158, 11, ${alpha.toFixed(3)})`
          ctx.fill()
        }
      }

      animId = requestAnimationFrame(render)
    }

    animId = requestAnimationFrame(render)

    return () => {
      cancelAnimationFrame(animId)
      window.removeEventListener('resize', handleResize)
    }
  }, [motion, inView])

  return (
    <div
      ref={containerRef}
      className={`pattern-waves-container ${className}`}
      aria-hidden="true"
    >
      {/* Warm amber diffuse backlight orbs */}
      <div className="pattern-waves-backlight">
        <div className="amber-glow-orb orb-center" />
        <div className="amber-glow-orb orb-right" />
      </div>

      {/* Dynamic Animated Canvas (when motion enabled) */}
      {motion ? (
        <canvas ref={canvasRef} className="pattern-waves-canvas" />
      ) : (
        /* Static High-Contrast Fallback (reduced motion or effects toggled off) */
        <div className="pattern-waves-static-fallback" />
      )}
    </div>
  )
}
