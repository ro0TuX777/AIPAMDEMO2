import React, { useState, useRef, useEffect, useCallback } from "react";
import { createPortal } from "react-dom";

interface InfoTooltipProps {
    text: string;
    /** Optional: override the icon. Defaults to a small "?" circle */
    children?: React.ReactNode;
    /** Max width of the tooltip popup in px */
    maxWidth?: number;
}

/**
 * A small inline "?" icon that shows a tooltip on hover.
 * Uses a portal + fixed positioning so it is never clipped by overflow containers.
 */
export const InfoTooltip: React.FC<InfoTooltipProps> = ({ text, children, maxWidth = 280 }) => {
    const [show, setShow] = useState(false);
    const triggerRef = useRef<HTMLSpanElement>(null);
    const [style, setStyle] = useState<React.CSSProperties>({});
    const [placement, setPlacement] = useState<"top" | "bottom">("top");

    const reposition = useCallback(() => {
        if (!triggerRef.current) return;
        const rect = triggerRef.current.getBoundingClientRect();
        const above = rect.top > 120;
        setPlacement(above ? "top" : "bottom");
        setStyle({
            position: "fixed",
            left: rect.left + rect.width / 2,
            ...(above
                ? { top: rect.top - 8 }
                : { top: rect.bottom + 8 }),
            transform: above ? "translate(-50%, -100%)" : "translateX(-50%)",
            maxWidth,
            zIndex: 9999,
        });
    }, [maxWidth]);

    useEffect(() => {
        if (show) reposition();
    }, [show, reposition]);

    return (
        <span
            ref={triggerRef}
            className="info-tooltip-trigger"
            onMouseEnter={() => setShow(true)}
            onMouseLeave={() => setShow(false)}
            onFocus={() => setShow(true)}
            onBlur={() => setShow(false)}
            tabIndex={0}
            role="button"
            aria-label="More info"
        >
            {children ?? (
                <span className="info-tooltip-icon">?</span>
            )}
            {show && createPortal(
                <span
                    className={`info-tooltip-popup ${placement === "bottom" ? "info-tooltip-popup--bottom" : ""}`}
                    style={style}
                    role="tooltip"
                >
                    {text}
                </span>,
                document.body,
            )}
        </span>
    );
};

