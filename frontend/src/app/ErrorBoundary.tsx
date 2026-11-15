import { Component } from 'react';
import type { ReactNode } from 'react';

export class ErrorBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  render() {
    if (this.state.failed) return (
      <main className="fatal-error" role="alert">
        <h1>Something went wrong</h1><p>The workspace could not be displayed.</p>
        <button className="button button-primary" onClick={() => this.setState({ failed: false })}>Try again</button>
      </main>
    );
    return this.props.children;
  }
}
