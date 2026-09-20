import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import 'leaflet/dist/leaflet.css';
import './style.css';
import App from './App';
import ErrorBoundary from './components/ErrorBoundary';
import GlobalErrorBridge from './components/GlobalErrorBridge';

const container = document.getElementById('root');
if (!container) {
  throw new Error('root element not found');
}

createRoot(container).render(
  <StrictMode>
    <ErrorBoundary>
      <GlobalErrorBridge>
        <App />
      </GlobalErrorBridge>
    </ErrorBoundary>
  </StrictMode>,
);
