interface PageHeaderProps {
  title: string
  description: string
}

export default function PageHeader({ title, description }: PageHeaderProps) {
  return (
    <header className="mb-8 border-b border-border-subtle pb-5">
      <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
      <p className="mt-2 max-w-[42rem] text-sm leading-6 text-ink-muted">
        {description}
      </p>
    </header>
  )
}
