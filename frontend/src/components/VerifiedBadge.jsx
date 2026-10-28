/** Green badge for a finding whose path a harmless sandboxed test confirmed. */
export default function VerifiedBadge({ small = false }) {
  return (
    <span className={`pill verified ${small ? 'small' : ''}`}
          title="Proof confirmed: a harmless marker test reached the risky call in a sandbox">
      <svg width="12" height="12" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
        <path d="m5 12.5 4.5 4.5L19 7.5" fill="none" stroke="currentColor" strokeWidth="3"
              strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      Verified
    </span>
  )
}

export const isProven = (finding) => finding?.confidence_tier === 'proof-confirmed'
