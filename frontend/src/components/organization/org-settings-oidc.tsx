"use client"

import { OIDCSettingsUpdate } from "@/client"
import { zodResolver } from "@hookform/resolvers/zod"
import { useForm } from "react-hook-form"
import { z } from "zod"

import { useAppInfo, useOrgOidcSettings } from "@/lib/hooks"
import { Button } from "@/components/ui/button"
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
} from "@/components/ui/form"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import { CenteredSpinner } from "@/components/loading/spinner"
import { AlertNotification } from "@/components/notifications"

const oidcFormSchema = z.object({
  oidc_enabled: z.boolean(),
  oidc_discovery_url: z.string().url().nullish(),
  oidc_client_id: z.string().nullish(),
  oidc_client_secret: z.string().nullish(),
})

type OidcFormValues = z.infer<typeof oidcFormSchema>

export function OrgSettingsOidcForm() {
  const { appInfo } = useAppInfo()
  const {
    oidcSettings,
    oidcSettingsIsLoading,
    oidcSettingsError,
    updateOidcSettings,
    updateOidcSettingsIsPending,
  } = useOrgOidcSettings()

  const form = useForm<OidcFormValues>({
    resolver: zodResolver(oidcFormSchema),
    values: {
      oidc_enabled: oidcSettings?.oidc_enabled ?? false,
      oidc_discovery_url: oidcSettings?.oidc_discovery_url,
      oidc_client_id: oidcSettings?.oidc_client_id,
      oidc_client_secret: "",
    },
  })

  const isOidcAllowed = appInfo?.auth_allowed_types.includes("oidc")
  const onSubmit = async (data: OidcFormValues) => {
    const conditional: Partial<OIDCSettingsUpdate> = {
      oidc_discovery_url: data.oidc_discovery_url ?? undefined,
      oidc_client_id: data.oidc_client_id ?? undefined,
      oidc_client_secret: data.oidc_client_secret || undefined,
    }
    if (isOidcAllowed) {
      conditional.oidc_enabled = data.oidc_enabled
    }
    try {
      await updateOidcSettings({
        requestBody: conditional,
      })
      form.reset({
        ...data,
        oidc_client_secret: "",
      })
    } catch {
      console.error("Failed to update oidc settings")
    }
  }

  if (oidcSettingsIsLoading) {
    return <CenteredSpinner />
  }
  if (oidcSettingsError || !oidcSettings) {
    return (
      <AlertNotification
        level="error"
        message={`Error loading OIDC settings: ${oidcSettingsError?.message || "Unknown error"}`}
      />
    )
  }

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-8">
        <FormField
          control={form.control}
          name="oidc_enabled"
          render={({ field }) => (
            <FormItem className="flex flex-row items-center justify-between rounded-lg border p-4">
              <div className="space-y-0.5">
                <FormLabel>Enable OIDC sign-in</FormLabel>
                <FormDescription>
                  Enable OpenID Connect authentication for your organization.
                </FormDescription>
              </div>
              <FormControl>
                <Switch
                  checked={isOidcAllowed && field.value}
                  onCheckedChange={field.onChange}
                  disabled={!isOidcAllowed}
                  aria-disabled={!isOidcAllowed}
                />
              </FormControl>
            </FormItem>
          )}
        />

        <FormField
          control={form.control}
          name="oidc_discovery_url"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Discovery URL</FormLabel>
              <FormControl>
                <Input
                  placeholder="https://idp.example.com/.well-known/openid-configuration"
                  {...field}
                  value={field.value ?? ""}
                />
              </FormControl>
              <FormDescription>
                OIDC provider discovery endpoint.
              </FormDescription>
            </FormItem>
          )}
        />

        <FormField
          control={form.control}
          name="oidc_client_id"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Client ID</FormLabel>
              <FormControl>
                <Input placeholder="client-id" {...field} value={field.value ?? ""} />
              </FormControl>
            </FormItem>
          )}
        />

        <FormField
          control={form.control}
          name="oidc_client_secret"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Client Secret</FormLabel>
              <FormControl>
                <Input
                  type="password"
                  placeholder={oidcSettings.oidc_client_secret_set ? "********" : "client secret"}
                  {...field}
                  value={field.value ?? ""}
                />
              </FormControl>
            </FormItem>
          )}
        />

        <Button type="submit" disabled={!isOidcAllowed || updateOidcSettingsIsPending}>
          Update OIDC settings
        </Button>
      </form>
    </Form>
  )
}
