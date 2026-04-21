import { Component } from 'react';
import type { ErrorInfo, ReactNode } from 'react';

interface Props {
  children: ReactNode;
  label?: string;
}

interface State {
  error: Error | null;
  info: ErrorInfo | null;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null, info: null };

  componentDidCatch(error: Error, info: ErrorInfo) {
    this.setState({ error, info });
    console.error('[ErrorBoundary]', this.props.label ?? '', error, info.componentStack);
  }

  render() {
    const { error, info } = this.state;
    if (error) {
      return (
        <div style={{
          padding: '24px',
          fontFamily: 'monospace',
          background: '#1a0a0a',
          color: '#ff8080',
          width: '100%',
          height: '100%',
          overflowY: 'auto',
          boxSizing: 'border-box',
        }}>
          <div style={{ fontSize: '1.1rem', fontWeight: 'bold', marginBottom: '12px' }}>
            🛑 React Fehler{this.props.label ? ` in ${this.props.label}` : ''}
          </div>
          <div style={{ color: '#ffb3b3', marginBottom: '8px' }}>{error.message}</div>
          <pre style={{ fontSize: '0.72rem', whiteSpace: 'pre-wrap', color: '#ff9999', marginBottom: '16px' }}>
            {error.stack}
          </pre>
          {info?.componentStack && (
            <pre style={{ fontSize: '0.68rem', whiteSpace: 'pre-wrap', color: '#cc7777' }}>
              {info.componentStack}
            </pre>
          )}
          <button
            onClick={() => this.setState({ error: null, info: null })}
            style={{
              marginTop: '16px',
              padding: '8px 20px',
              background: '#7f1d1d',
              color: '#fff',
              border: 'none',
              borderRadius: '8px',
              cursor: 'pointer',
              fontSize: '0.85rem',
            }}
          >
            Neu versuchen
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
