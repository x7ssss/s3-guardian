import { randomUUID } from "node:crypto";

export type AuditEventType =
  | "DISCOVERY"
  | "BLAST_RADIUS_ASSESSMENT"
  | "CANARY_VERIFIED"
  | "REMEDIATION_EXECUTED"
  | "CIRCUIT_BREAKER_TRIPPED"
  | "REMEDIATION_ROLLED_BACK";

export interface AuditEvent {
  eventId: string; // UUIDv4
  timestamp: string; // ISO 8601
  eventType: AuditEventType;
  accountId: string;
  bucketName: string;
  targetCount?: number;
  bytesFreed?: number;
  estimatedSavingsUSD?: number;
  planHash?: string;
  xAmzRequestIds?: string[];
  details?: Record<string, any>;
}

export interface BucketAggregate {
  accountId: string;
  bucketName: string;
  totalBytesFreed: number;
  totalEstimatedSavingsUSD: number;
  eventCount: number;
  lastSeenPlanHash?: string;
  lastEventTimestamp: string;
  circuitBreakerTrips: number;
  details?: Record<string, any>;
}

export interface CompactionSnapshot {
  snapshotVersion: string;
  compactedAt: string;
  sourceEventsCount: number;
  buckets: Record<string, BucketAggregate>;
}

export function createAuditEvent(
  params: Omit<AuditEvent, "eventId" | "timestamp"> & {
    eventId?: string;
    timestamp?: string;
  }
): AuditEvent {
  return {
    eventId: params.eventId ?? randomUUID(),
    timestamp: params.timestamp ?? new Date().toISOString(),
    eventType: params.eventType,
    accountId: params.accountId,
    bucketName: params.bucketName,
    targetCount: params.targetCount,
    bytesFreed: params.bytesFreed,
    estimatedSavingsUSD: params.estimatedSavingsUSD,
    planHash: params.planHash,
    xAmzRequestIds: params.xAmzRequestIds,
    details: params.details,
  };
}
