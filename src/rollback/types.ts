export type MutationType =
  | "LIFECYCLE_CONFIGURATION"
  | "BUCKET_TAGGING"
  | "SOFT_DELETE_MARKER"
  | "OBJECT_DELETION";

export type InverseCommandType =
  | "PutBucketLifecycleConfiguration"
  | "DeleteBucketLifecycleConfiguration"
  | "PutBucketTagging"
  | "DeleteBucketTagging"
  | "DeleteObjects";

export interface UndoManifest {
  manifestId: string; // UUIDv4
  manifestVersion: "1.8.0";
  createdAt: string; // ISO 8601
  bucketName: string;
  mutationType: MutationType;
  canonicalPreStateHash: string; // 64-char hex SHA-256
  canonicalPostStateHash: string; // 64-char hex SHA-256
  preState: any; // null if 404 NoSuchLifecycleConfiguration
  postState: any;
  inverseCommandType: InverseCommandType;
  inversePayload: any;
  appliedPlanHash: string;
  requestIds: string[];
}

export type IrreversibleOperation =
  | "PERMANENT_VERSION_DELETE"
  | "ABORT_MULTIPART_UPLOAD";

export interface DeletionCertificateLedgerItem {
  key: string;
  versionId?: string;
  uploadId?: string;
  sizeBytes?: number;
}

export interface DeletionCertificate {
  certificateId: string; // UUIDv4
  timestamp: string; // ISO 8601
  bucketName: string;
  operation: IrreversibleOperation;
  targetCount: number;
  totalBytesReclaimed: number;
  planHash: string;
  requestIds: string[];
  itemLedger: DeletionCertificateLedgerItem[];
}

export class RemoteStateDriftError extends Error {
  public readonly bucketName: string;
  public readonly expectedHash: string;
  public readonly actualHash: string;

  constructor(bucketName: string, expectedHash: string, actualHash: string, message?: string) {
    super(
      message ??
        `Remote state drift detected for bucket '${bucketName}'. Expected post-state hash '${expectedHash}', but live remote state hash is '${actualHash}'. Pass --force to override.`
    );
    this.name = "RemoteStateDriftError";
    this.bucketName = bucketName;
    this.expectedHash = expectedHash;
    this.actualHash = actualHash;
  }
}

export interface RollbackResult {
  manifestId: string;
  bucketName: string;
  status: "RESTORED";
  restoredAt: string;
}

export interface StateCaptureResult<T = any> {
  preState: T | null;
  state: T | null;
  canonicalHash: string;
  hash: string;
}
