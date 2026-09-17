/** Abstract initial badge. Not a vendor mark. Color comes from --provider-color. */
export default function InitialMark({ name }: { name: string }) {
  const initial = (name.trim().charAt(0) || '?').toLocaleUpperCase()
  return (
    <span aria-hidden="true" className="provider-mark">
      {initial}
    </span>
  )
}
