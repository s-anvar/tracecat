"use client"

import { ComponentPropsWithoutRef, useState } from "react"
import { buildUrl } from "@/lib/ss-utils"

import { Button } from "@/components/ui/button"
import { Icons } from "@/components/icons"

export type OidcButtonProps = ComponentPropsWithoutRef<typeof Button>
export function OidcSSOButton(props: OidcButtonProps) {
  const [isLoading, setIsLoading] = useState<boolean>(false)
  const handleClick = async () => {
    try {
      setIsLoading(true)
      const params = new URLSearchParams()
      for (const scope of ["openid", "email", "profile"]) {
        params.append("scopes", scope)
      }
      const resp = await fetch(
        buildUrl(`/auth/oidc/authorize?${params.toString()}`)
      )
      const { authorization_url } = await resp.json()
      window.location.href = authorization_url
    } catch (error) {
      console.error("Error authorizing with OIDC", error)
    } finally {
      setIsLoading(false)
    }
  }
  return (
    <Button {...props} variant="outline" onClick={handleClick} disabled={isLoading}>
      {isLoading ? (
        <Icons.spinner className="mr-2 size-4 animate-spin" />
      ) : (
        <Icons.oidc className="mr-2 size-4" />
      )}{" "}
      OpenID Connect
    </Button>
  )
}
