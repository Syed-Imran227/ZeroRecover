export interface DriveInfo {
  letter: string;
  label: string;
  total_size: number;
  free_size: number;
  file_system: string;
  is_removable: boolean;
  drive_type: string; // "SSD", "HDD", or "Unknown"
}

export interface WipeResult {
  success: boolean;
  target: string;
  method: string;
  bytes_wiped: number;
  passes_completed: number;
  duration_ms: number;
  timestamp: string;
  device_id: string;
  hash: string;
  error_message?: string;
}

export interface WipeProgress {
  current_pass: number;
  total_passes: number;
  bytes_processed: number;
  total_bytes: number;
  percentage: number;
  current_operation: string;
}

export type WipeMethod = 
  | "NIST SP 800-88"
  | "DoD 5220.22-M"
  | "Gutmann"
  | "Random"
  | "Zero";

export interface WipeStatus {
  isWiping: boolean;
  progress: WipeProgress | null;
  result: WipeResult | null;
  error: string | null;
  certificatePath: string | null;
}
