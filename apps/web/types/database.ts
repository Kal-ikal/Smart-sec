export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[];

export type AppRole = "admin" | "analyst" | "viewer";
export type JobStatus = "queued" | "claimed" | "running" | "completed" | "failed";
export type CvssSeverity = "None" | "Low" | "Medium" | "High" | "Critical";

export type Database = {
  public: {
    Tables: {
      findings: {
        Row: {
          created_at: string;
          cwe_id: number | null;
          description: string | null;
          evidence: string | null;
          id: string;
          job_id: string;
          name: string;
          owasp_category: string | null;
          owner_id: string;
          risk_zap: string | null;
          cvss_base_score: number | null;
          cvss_composite_score: number | null;
          cvss_environmental_score: number | null;
          cvss_severity: CvssSeverity | null;
          cvss_threat_score: number | null;
          cvss_vector: string | null;
          solution: string | null;
          target_id: string;
          zap_alert_id: string | null;
          zap_plugin_id: string | null;
        };
        Insert: {
          created_at?: string;
          cwe_id?: number | null;
          description?: string | null;
          evidence?: string | null;
          id?: string;
          job_id: string;
          name: string;
          owasp_category?: string | null;
          owner_id: string;
          risk_zap?: string | null;
          cvss_base_score?: number | null;
          cvss_composite_score?: number | null;
          cvss_environmental_score?: number | null;
          cvss_severity?: CvssSeverity | null;
          cvss_threat_score?: number | null;
          cvss_vector?: string | null;
          solution?: string | null;
          target_id: string;
          zap_alert_id?: string | null;
          zap_plugin_id?: string | null;
        };
        Update: {
          created_at?: string;
          cwe_id?: number | null;
          description?: string | null;
          evidence?: string | null;
          id?: string;
          job_id?: string;
          name?: string;
          owasp_category?: string | null;
          owner_id?: string;
          risk_zap?: string | null;
          cvss_base_score?: number | null;
          cvss_composite_score?: number | null;
          cvss_environmental_score?: number | null;
          cvss_severity?: CvssSeverity | null;
          cvss_threat_score?: number | null;
          cvss_vector?: string | null;
          solution?: string | null;
          target_id?: string;
          zap_alert_id?: string | null;
          zap_plugin_id?: string | null;
        };
        Relationships: [
          {
            foreignKeyName: "findings_job_id_fkey";
            columns: ["job_id"];
            isOneToOne: false;
            referencedRelation: "scan_jobs";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "findings_owner_id_fkey";
            columns: ["owner_id"];
            isOneToOne: false;
            referencedRelation: "profiles";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "findings_target_id_fkey";
            columns: ["target_id"];
            isOneToOne: false;
            referencedRelation: "scan_targets";
            referencedColumns: ["id"];
          }
        ];
      };
      profiles: {
        Row: {
          created_at: string;
          full_name: string | null;
          id: string;
          role: Database["public"]["Enums"]["app_role"];
        };
        Insert: {
          created_at?: string;
          full_name?: string | null;
          id: string;
          role?: Database["public"]["Enums"]["app_role"];
        };
        Update: {
          created_at?: string;
          full_name?: string | null;
          id?: string;
          role?: Database["public"]["Enums"]["app_role"];
        };
        Relationships: [];
      };
      scan_jobs: {
        Row: {
          claimed_at: string | null;
          claimed_by: string | null;
          created_at: string;
          error_message: string | null;
          finished_at: string | null;
          id: string;
          owner_id: string;
          started_at: string | null;
          status: Database["public"]["Enums"]["job_status"];
          target_id: string;
          zap_scan_id: string | null;
        };
        Insert: {
          claimed_at?: string | null;
          claimed_by?: string | null;
          created_at?: string;
          error_message?: string | null;
          finished_at?: string | null;
          id?: string;
          owner_id: string;
          started_at?: string | null;
          status?: Database["public"]["Enums"]["job_status"];
          target_id: string;
          zap_scan_id?: string | null;
        };
        Update: {
          claimed_at?: string | null;
          claimed_by?: string | null;
          created_at?: string;
          error_message?: string | null;
          finished_at?: string | null;
          id?: string;
          owner_id?: string;
          started_at?: string | null;
          status?: Database["public"]["Enums"]["job_status"];
          target_id?: string;
          zap_scan_id?: string | null;
        };
        Relationships: [
          {
            foreignKeyName: "scan_jobs_owner_id_fkey";
            columns: ["owner_id"];
            isOneToOne: false;
            referencedRelation: "profiles";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "scan_jobs_target_id_fkey";
            columns: ["target_id"];
            isOneToOne: false;
            referencedRelation: "scan_targets";
            referencedColumns: ["id"];
          }
        ];
      };
      scan_targets: {
        Row: {
          created_at: string;
          id: string;
          is_authorized: boolean;
          notes: string | null;
          owner_id: string;
          program_name: string | null;
          url: string;
        };
        Insert: {
          created_at?: string;
          id?: string;
          is_authorized?: boolean;
          notes?: string | null;
          owner_id: string;
          program_name?: string | null;
          url: string;
        };
        Update: {
          created_at?: string;
          id?: string;
          is_authorized?: boolean;
          notes?: string | null;
          owner_id?: string;
          program_name?: string | null;
          url?: string;
        };
        Relationships: [
          {
            foreignKeyName: "scan_targets_owner_id_fkey";
            columns: ["owner_id"];
            isOneToOne: false;
            referencedRelation: "profiles";
            referencedColumns: ["id"];
          }
        ];
      };
    };
    Views: {
      [_ in never]: never;
    };
    Functions: {
      calculate_cvss_v4: {
        Args: {
          p_vector: string;
        };
        Returns: {
          base_score: number;
          composite_score: number;
          environmental_score: number;
          severity: CvssSeverity;
          threat_score: number;
        }[];
      };
      claim_next_scan_job: {
        Args: {
          p_worker_id: string;
        };
        Returns: {
          claimed_at: string | null;
          claimed_by: string | null;
          created_at: string;
          error_message: string | null;
          finished_at: string | null;
          id: string;
          owner_id: string;
          started_at: string | null;
          status: Database["public"]["Enums"]["job_status"];
          target_id: string;
          zap_scan_id: string | null;
        }[];
      };
    };
    Enums: {
      app_role: "admin" | "analyst" | "viewer";
      job_status: "queued" | "claimed" | "running" | "completed" | "failed";
    };
    CompositeTypes: {
      [_ in never]: never;
    };
  };
};
