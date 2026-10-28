import { useEffect } from 'react'
import { useThree } from '@react-three/fiber'

/**
 * Requests a frame whenever `value` changes. Switching a canvas from frameloop "demand" back to
 * "always" does not restart a render loop that has stopped; this kicks it off again.
 */
export default function WakeOnChange({ value }) {
  const invalidate = useThree((state) => state.invalidate)
  useEffect(() => { invalidate() }, [value, invalidate])
  return null
}
