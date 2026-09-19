import { useEffect } from 'react';
import { createPortal } from 'react-dom';

export interface ContextMenuItem {
  label: string;
  hint?: string;
  danger?: boolean;
  disabled?: boolean;
  onSelect: () => void;
}

interface ContextMenuProps {
  x: number;
  y: number;
  title?: string;
  items: ContextMenuItem[];
  onClose: () => void;
}

const ContextMenu = ({ x, y, title, items, onClose }: ContextMenuProps) => {
  useEffect(() => {
    const close = () => onClose();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('pointerdown', close);
    window.addEventListener('blur', close);
    window.addEventListener('keydown', onKeyDown);
    return () => {
      window.removeEventListener('pointerdown', close);
      window.removeEventListener('blur', close);
      window.removeEventListener('keydown', onKeyDown);
    };
  }, [onClose]);

  return createPortal(
    <div
      className="ctx-menu"
      style={{ left: x, top: y }}
      role="menu"
      onPointerDown={(event) => event.stopPropagation()}
      onContextMenu={(event) => {
        event.preventDefault();
        event.stopPropagation();
      }}
    >
      {title && <div className="ctx-menu-title selectable">{title}</div>}
      {items.map((item) => (
        <button
          key={item.label}
          type="button"
          role="menuitem"
          className={`ctx-menu-item${item.danger ? ' ctx-menu-item--danger' : ''}`}
          disabled={item.disabled}
          title={item.disabled ? item.hint : undefined}
          onClick={() => {
            onClose();
            item.onSelect();
          }}
        >
          <span className="ctx-menu-label">{item.label}</span>
          {item.hint && <span className="ctx-menu-hint">{item.hint}</span>}
        </button>
      ))}
    </div>,
    document.body,
  );
};

export default ContextMenu;
