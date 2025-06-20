import { getBaseUrl } from "@/lib/api"

export function buildUrl(path: string) {
  const url = getBaseUrl()
  if (path.startsWith("/")) {
    return `${url}${path}`
  }
  return `${url}/${path}`
}
