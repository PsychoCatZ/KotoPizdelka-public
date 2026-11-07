import QRCode from "qrcode";
import { compactQrLink, restoreQrLink, LINK_PREFIX, MAX_INVITATION_LINK_LENGTH } from "./compactInvitation";
export { MAX_INVITATION_LINK_LENGTH } from "./compactInvitation";

/** The fragment is an opaque capability: never fetch it or send it to a QR service. */

export function normalizeInvitationLink(value: string): string {
  const link = value.trim();
  if (link.length > MAX_INVITATION_LINK_LENGTH || !link.startsWith(LINK_PREFIX) || !/^[A-Za-z0-9_-]+$/.test(link.slice(LINK_PREFIX.length))) {
    throw new Error("Вставьте ссылку-приглашение КотоПизделки целиком.");
  }
  try { return restoreQrLink(link); }
  catch { throw new Error("QR-код приглашения повреждён или имеет неподдерживаемый формат."); }
}

export interface InvitationQr { size: number; path: string }

/** Keep every module an integer number of screen pixels, including at display scaling. */
export function invitationQrDisplaySize(size: number, availableWidth: number, availableHeight: number, pixelRatio: number, enlarged = false): number {
  if (!Number.isInteger(size) || size <= 0 || !Number.isFinite(availableWidth) || !Number.isFinite(availableHeight) || !Number.isFinite(pixelRatio) || availableWidth <= 0 || availableHeight <= 0 || pixelRatio <= 0) return 0;
  const available = Math.min(availableWidth, availableHeight, enlarged ? 750 : 500);
  const modulePixels = Math.floor((available * pixelRatio + 1e-7) / size);
  return modulePixels > 0 ? size * modulePixels / pixelRatio : 0;
}

/** All SVG coordinates come from the local matrix, never from invitation text. */
export function invitationQr(value: string): InvitationQr {
  const link = normalizeInvitationLink(value);
  const { modules } = QRCode.create(compactQrLink(link), { errorCorrectionLevel: "M" });
  const paths: string[] = [];
  for (let y = 0; y < modules.size; y++) {
    for (let x = 0; x < modules.size; x++) {
      if (modules.get(y, x)) paths.push(`M${x + 4} ${y + 4}h1v1h-1z`);
    }
  }
  return { size: modules.size + 8, path: paths.join("") };
}
