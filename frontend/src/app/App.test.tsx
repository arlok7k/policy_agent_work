import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { App } from './App';

describe('frontend scaffold', () => {
  it('renders the application without unsafe HTML', () => {
    render(<App />);
    expect(screen.getByRole('heading', { name: 'SMART SOC' })).toBeInTheDocument();
    expect(screen.getByText('Host baseline scaffold')).toBeInTheDocument();
  });
});
