import type { ReactNode } from 'react';

interface ModalProps {
  title: string;
  subtitle?: ReactNode;
  ariaLabel: string;
  /** Extra class names appended after the shared "modal modal--scan". */
  variant?: string;
  onClose: () => void;
  footer?: ReactNode;
  children: ReactNode;
}

/**
 * Modal is the shared shell for the app's dialogs: backdrop, header with title
 * and close button, scrollable body and an optional footer.
 */
const Modal = ({
  title,
  subtitle,
  ariaLabel,
  variant,
  onClose,
  footer,
  children,
}: ModalProps) => (
  <div className="modal-backdrop" onClick={onClose}>
    <div
      className={`modal modal--scan${variant ? ` ${variant}` : ''}`}
      role="dialog"
      aria-modal="true"
      aria-label={ariaLabel}
      onClick={(event) => event.stopPropagation()}
    >
      <div className="modal-head">
        <div>
          <div className="modal-title">{title}</div>
          {subtitle != null && <div className="modal-sub selectable">{subtitle}</div>}
        </div>
        <button type="button" className="modal-close" onClick={onClose} aria-label="Close">
          ×
        </button>
      </div>

      <div className="modal-body">{children}</div>

      {footer != null && <div className="modal-foot">{footer}</div>}
    </div>
  </div>
);

export default Modal;
