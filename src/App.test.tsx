import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App'

beforeEach(() => {
  window.localStorage.clear()
  vi.spyOn(window.navigator, 'language', 'get').mockReturnValue('en-US')
})

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  window.localStorage.clear()
})

describe('App accessibility', () => {
  it('renders a skip link targeting the report content region', () => {
    render(<App />)

    expect(screen.getByRole('link', { name: 'Footprint summary' })).toHaveAttribute('href', '#report-content')
    expect(document.querySelector('#report-content')).toBeInTheDocument()
  })

  it('labels the domain input from the default locale and links helper and validation error text', () => {
    render(<App />)

    const input = screen.getByLabelText('Domain')
    expect(input).toHaveAttribute('aria-describedby', 'domain-help domain-error')
    expect(document.querySelector('#domain-help')).toHaveTextContent(
      'Enter one domain. Protocols, paths, ports, and casing are normalized before any lookup.',
    )

    fireEvent.click(screen.getByRole('button', { name: 'Build atlas' }))

    expect(screen.getByRole('alert')).toHaveAttribute('id', 'domain-error')
    expect(screen.getByRole('alert')).toHaveTextContent('Enter a domain before running the atlas.')
    expect(input).toHaveAccessibleDescription(
      'Enter one domain. Protocols, paths, ports, and casing are normalized before any lookup. Enter a domain before running the atlas.',
    )
  })
})
