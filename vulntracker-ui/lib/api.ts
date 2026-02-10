import type {
  PaginatedResponse,
  CveListItem,
  CveDetail,
  Vendor,
  Product,
  Weakness,
} from "./types";

// Determine the base URL based on environment
function getBaseUrl(): string {
  // Server-side: use localhost with the port
  if (typeof window === "undefined") {
    // During build time or SSR, use the environment variable or default
    const port = process.env.PORT || 3000;
    return `http://localhost:${port}`;
  }
  // Client-side: use relative URLs
  return "";
}

const API_BASE = "/api";

class ApiError extends Error {
  constructor(
    public status: number,
    message: string
  ) {
    super(message);
    this.name = "ApiError";
  }
}

// Fetch with caching enabled (for read-heavy, slow-changing data)
async function fetchApiCached<T>(
  endpoint: string,
  options?: RequestInit
): Promise<T> {
  const baseUrl = getBaseUrl();
  const url = `${baseUrl}${API_BASE}${endpoint}`;

  const res = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
    // Allow Next.js default caching + revalidate after 60 seconds
    next: { revalidate: 60 },
  });

  if (!res.ok) {
    throw new ApiError(res.status, `API error: ${res.status} ${res.statusText}`);
  }

  return res.json();
}

// Fetch without caching (for fresh data)
async function fetchApiFresh<T>(
  endpoint: string,
  options?: RequestInit
): Promise<T> {
  const baseUrl = getBaseUrl();
  const url = `${baseUrl}${API_BASE}${endpoint}`;

  const res = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
    cache: "no-store",
  });

  if (!res.ok) {
    throw new ApiError(res.status, `API error: ${res.status} ${res.statusText}`);
  }

  return res.json();
}

// ============ CVE Endpoints ============

export type CveSortOption = '-updated_at' | 'updated_at' | '-created_at' | 'created_at' | '-cvss' | 'cvss';

export async function getCves(
  page = 1,
  sort: CveSortOption = '-created_at'
): Promise<PaginatedResponse<CveListItem>> {
  // Use cached fetch - count is cached on server, results are fresh
  return fetchApiCached<PaginatedResponse<CveListItem>>(`/cve?page=${page}&sort=${sort}`);
}

export async function getCve(cveId: string): Promise<CveDetail> {
  // CVE detail should be fresh (might have been updated)
  return fetchApiFresh<CveDetail>(`/cve/${cveId}`);
}

// ============ Vendor Endpoints ============

export async function getVendors(
  page = 1
): Promise<PaginatedResponse<Vendor>> {
  // Vendors list is cached on server - use cached fetch
  return fetchApiCached<PaginatedResponse<Vendor>>(`/vendors?page=${page}`);
}

export async function getVendor(name: string): Promise<Vendor> {
  // Vendor detail is cached on server
  return fetchApiCached<Vendor>(`/vendors/${encodeURIComponent(name)}`);
}

export async function getVendorCves(
  vendorName: string,
  page = 1
): Promise<PaginatedResponse<CveListItem>> {
  // CVE lists should be relatively fresh
  return fetchApiCached<PaginatedResponse<CveListItem>>(
    `/vendors/${encodeURIComponent(vendorName)}/cve?page=${page}`
  );
}

export async function getVendorProducts(
  vendorName: string,
  page = 1
): Promise<PaginatedResponse<Product>> {
  return fetchApiCached<PaginatedResponse<Product>>(
    `/vendors/${encodeURIComponent(vendorName)}/products?page=${page}`
  );
}

// ============ Product Endpoints ============

export async function getProductCves(
  vendorName: string,
  productName: string,
  page = 1
): Promise<PaginatedResponse<CveListItem>> {
  return fetchApiCached<PaginatedResponse<CveListItem>>(
    `/vendors/${encodeURIComponent(vendorName)}/products/${encodeURIComponent(productName)}/cve?page=${page}`
  );
}

// ============ Weakness Endpoints ============

export async function getWeaknesses(
  page = 1
): Promise<PaginatedResponse<Weakness>> {
  return fetchApiCached<PaginatedResponse<Weakness>>(`/weaknesses?page=${page}`);
}

export async function getWeaknessCves(
  cweId: string,
  page = 1
): Promise<PaginatedResponse<CveListItem>> {
  return fetchApiCached<PaginatedResponse<CveListItem>>(
    `/weaknesses/${encodeURIComponent(cweId)}/cve?page=${page}`
  );
}

// ============ Utility ============

export { ApiError };
