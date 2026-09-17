import { useEffect } from 'react';

interface MissingToolModalProps {
  open: boolean;
  message: string;
  hint: string;
  onClose: () => void;
}

const MissingToolModal = ({ open, message, hint, onClose }: MissingToolModalProps) => {
  useEffect(() => {
    if (!open) {
      return;
    }
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [open, onClose]);

  if (!open) {
    return null;
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div
        className="modal modal--tool"
        role="alertdialog"
        aria-modal="true"
        aria-label="Missing dependency"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="modal-head">
          <div>
            <div className="modal-title modal-title--error">MISSING DEPENDENCY</div>
            <div className="modal-sub">No traceroute tool was found on this system</div>
          </div>
          <button type="button" className="modal-close" onClick={onClose} aria-label="Close">
            ×
          </button>
        </div>

        <div className="modal-body">
          <p className="tool-error-message">{message}</p>

          {hint && (
            <div className="tool-error-hint">
              <div className="field-label">HOW TO FIX</div>
              <p>{hint}</p>
            </div>
          )}

          <p className="tool-error-note">
            Traceroute Map drives your operating system's traceroute implementation —
            <code> traceroute</code>, <code>tracepath</code> or <code>mtr</code> on Unix,
            <code> tracert</code> on Windows. Install one of them, then restart the app.
          </p>
        </div>

        <div className="modal-foot">
          <button type="button" className="btn btn--primary" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

export default MissingToolModal;
