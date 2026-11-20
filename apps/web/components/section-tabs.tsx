import type { ReactNode } from 'react'

export function SectionTabs<T extends string>({ label, value, onChange, options }: {
  label: string
  value: T
  onChange: (value: T) => void
  options: ReadonlyArray<readonly [T, ReactNode]>
}) {
  return <div className="tabs release-tabs section-tabs" role="group" aria-label={label}>
    {options.map(([id, name]) => <button key={id} type="button"
      aria-pressed={value === id} className={value === id ? 'active' : ''}
      onClick={() => onChange(id)}>{name}</button>)}
  </div>
}
