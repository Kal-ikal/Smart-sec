import { createClient } from "@supabase/supabase-js";
import { config } from "../config.js";

/**
 * Klien Supabase dengan SERVICE ROLE key -- melewati RLS sepenuhnya.
 * Ini SATU-SATUNYA tempat di seluruh proyek yang boleh memuat service
 * role key. Jangan pernah mengimpor modul ini dari apps/web.
 */
export const supabaseAdmin = createClient(
  config.supabaseUrl,
  config.supabaseServiceRoleKey,
  {
    auth: { persistSession: false, autoRefreshToken: false },
  }
);
