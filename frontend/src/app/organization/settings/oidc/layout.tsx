import { Metadata } from "next"

export const metadata: Metadata = {
  title: "OIDC | Organization",
}

export default function OIDCLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return children
}
