export interface AuditLogEntity {
  id: string;
  userId: string | null;
  event: string;
  ip: string | null;
  userAgent: string | null;
  metadata: Record<string, unknown>;
  createdAt: Date;
}
