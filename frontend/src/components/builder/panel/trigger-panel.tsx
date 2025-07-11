"use client"

import "react18-json-view/src/style.css"

import { zodResolver } from "@hookform/resolvers/zod"
import { CheckIcon, DotsHorizontalIcon } from "@radix-ui/react-icons"
import { CalendarClockIcon, PlusCircleIcon, WebhookIcon } from "lucide-react"
import { useForm } from "react-hook-form"
import { z } from "zod"
import {
  $WebhookMethod,
  ApiError,
  type WebhookMethod,
  type WebhookRead,
  type WorkflowRead,
} from "@/client"
import { TriggerTypename } from "@/components/builder/canvas/trigger-node"
import { CopyButton } from "@/components/copy-button"
import { getIcon } from "@/components/icons"
import { CenteredSpinner } from "@/components/loading/spinner"
import { AlertNotification } from "@/components/notifications"
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Separator } from "@/components/ui/separator"
import { Switch } from "@/components/ui/switch"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import { toast } from "@/components/ui/use-toast"
import { useSchedules, useUpdateWebhook } from "@/lib/hooks"
import {
  durationSchema,
  durationToHumanReadable,
  durationToISOString,
} from "@/lib/time"
import { cn } from "@/lib/utils"
import { useWorkflow } from "@/providers/workflow"
import { useWorkspace } from "@/providers/workspace"

const HTTP_METHODS: readonly WebhookMethod[] = $WebhookMethod.enum

export function TriggerPanel({ workflow }: { workflow: WorkflowRead }) {
  return (
    <div className="size-full overflow-auto">
      <div className="grid grid-cols-3">
        <div className="col-span-2 overflow-hidden">
          <h3 className="p-4">
            <div className="flex w-full items-center space-x-4">
              {getIcon(TriggerTypename, {
                className: "size-10 p-2",
                flairsize: "md",
              })}
              <div className="flex w-full flex-1 justify-between space-x-12">
                <div className="flex flex-col">
                  <div className="flex w-full items-center justify-between text-xs font-medium leading-none">
                    <div className="flex w-full">Trigger</div>
                  </div>
                  <p className="mt-2 text-xs text-muted-foreground">
                    Workflow Triggers
                  </p>
                </div>
              </div>
            </div>
          </h3>
        </div>
      </div>
      <Separator />
      {/* Metadata */}
      <Accordion
        type="multiple"
        defaultValue={[
          "trigger-settings",
          "trigger-webhooks",
          "trigger-schedules",
        ]}
      >
        {/* Webhooks */}
        <AccordionItem value="trigger-webhooks">
          <AccordionTrigger className="px-4 text-xs font-bold">
            <div className="flex items-center">
              <WebhookIcon className="mr-3 size-4" />
              <span>Webhook</span>
            </div>
          </AccordionTrigger>
          <AccordionContent>
            <div className="my-4 space-y-2 px-4">
              <WebhookControls
                webhook={workflow.webhook}
                workflowId={workflow.id}
              />
            </div>
          </AccordionContent>
        </AccordionItem>

        {/* Schedules */}
        <AccordionItem value="trigger-schedules">
          <AccordionTrigger className="px-4 text-xs font-bold">
            <div className="flex items-center">
              <CalendarClockIcon className="mr-3 size-4" />
              <span>Schedules</span>
            </div>
          </AccordionTrigger>
          <AccordionContent>
            <div className="my-4 space-y-2 px-4">
              <ScheduleControls workflowId={workflow.id} />
            </div>
          </AccordionContent>
        </AccordionItem>
      </Accordion>
    </div>
  )
}

export function WebhookControls({
  webhook: { url, status, methods = ["POST"] },
  workflowId,
}: {
  webhook: WebhookRead
  workflowId: string
}) {
  const { workspaceId } = useWorkspace()
  const { mutateAsync } = useUpdateWebhook(workspaceId, workflowId)

  const onCheckedChange = async (checked: boolean) => {
    await mutateAsync({
      status: checked ? "online" : "offline",
    })
  }

  const onMethodsChange = async (newMethods: WebhookMethod[]) => {
    if (newMethods.length === 0) {
      console.log("No methods selected")
      return
    }

    try {
      await mutateAsync({
        methods: newMethods,
      })
      toast({
        title: "Webhook methods updated",
        description: `The webhook will accept requests via: ${newMethods.sort().join(", ")}`,
      })
    } catch (error) {
      console.log("Failed to update webhook methods", error)
    }
  }

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <Label
            htmlFor="webhook-toggle"
            className="flex items-center gap-2 text-xs font-medium"
          >
            <span>Toggle Webhook</span>
          </Label>
          <Switch
            id="webhook-toggle"
            checked={status === "online"}
            onCheckedChange={onCheckedChange}
            className="data-[state=checked]:bg-emerald-500"
          />
        </div>
        <div className="text-xs text-muted-foreground">
          {status === "online"
            ? "Webhook is currently active and receiving requests"
            : "Webhook is disabled"}
        </div>
      </div>

      <div className="space-y-2">
        <Label className="flex items-center gap-2 text-xs font-medium">
          <span>Allowed HTTP Methods</span>
        </Label>
        <div className="relative w-full">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="outline"
                role="combobox"
                className="w-full justify-between text-xs"
              >
                {methods.length > 0
                  ? methods.sort().join(", ")
                  : "Select HTTP methods"}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent
              style={{ width: "var(--radix-dropdown-menu-trigger-width)" }}
              align="start"
              sideOffset={4}
            >
              {HTTP_METHODS.map((method) => (
                <DropdownMenuItem
                  key={method}
                  onClick={() => {
                    const newMethods = methods.includes(method)
                      ? methods.filter((m) => m !== method)
                      : [...methods, method]

                    onMethodsChange(newMethods)
                  }}
                  className="w-full text-xs"
                >
                  <CheckIcon
                    className={cn(
                      "mr-2 size-4",
                      methods.includes(method) ? "opacity-100" : "opacity-0"
                    )}
                  />
                  <span>{method}</span>
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>

      <div className="space-y-2">
        <Label className="flex items-center gap-2 text-xs font-medium">
          <span>URL</span>
          <CopyButton value={url} toastMessage="Copied URL to clipboard" />
        </Label>
        <div className="rounded-md border shadow-sm">
          <Input
            name="url"
            defaultValue={url}
            className="rounded-md border-none text-xs shadow-none"
            readOnly
            disabled
          />
        </div>
      </div>
    </div>
  )
}

export function ScheduleControls({ workflowId }: { workflowId: string }) {
  const {
    schedules,
    schedulesIsLoading,
    schedulesError,
    updateSchedule,
    deleteSchedule,
  } = useSchedules(workflowId)
  const { workspaceId } = useWorkspace()

  if (schedulesIsLoading) {
    return <CenteredSpinner />
  }
  if (schedulesError || !schedules) {
    return (
      <AlertNotification
        title="Failed to load schedules"
        message="There was an error when loading schedules."
      />
    )
  }

  return (
    <div className="rounded-lg border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="pl-3 text-xs font-semibold">
              Schedule ID
            </TableHead>
            <TableHead className="text-xs font-semibold">Interval</TableHead>
            <TableHead className="text-xs font-semibold">Status</TableHead>
            <TableHead className="text-xs font-semibold">Timeout</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {schedules.length > 0 ? (
            schedules.map(({ id, status, every, timeout }) => (
              <TableRow key={id} className="ext-xs text-muted-foreground">
                <TableCell className="items-center pl-3 text-xs">
                  {id}
                </TableCell>
                <TableCell className="items-center text-xs">
                  {durationToHumanReadable(every)}
                </TableCell>
                <TableCell className="text-xs capitalize">
                  <div className="flex">
                    <p>{status}</p>
                  </div>
                </TableCell>
                <TableCell className="text-xs capitalize">
                  <div className="flex">
                    <p>{timeout ? `${timeout}s` : "None"}</p>
                  </div>
                </TableCell>
                <TableCell className="items-center pr-3 text-xs">
                  <div className="flex justify-end">
                    <AlertDialog>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button className="size-6 p-0" variant="ghost">
                            <DotsHorizontalIcon className="size-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent>
                          <DropdownMenuLabel className="text-xs">
                            Actions
                          </DropdownMenuLabel>
                          <DropdownMenuItem
                            onClick={() => navigator.clipboard.writeText(id!)}
                            className="text-xs"
                          >
                            Copy ID
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem
                            className={cn("text-xs", status === "online")}
                            onClick={async () =>
                              await updateSchedule({
                                workspaceId,
                                scheduleId: id!,
                                requestBody: {
                                  status:
                                    status === "online" ? "offline" : "online",
                                },
                              })
                            }
                          >
                            {status === "online" ? "Pause" : "Unpause"}
                          </DropdownMenuItem>
                          <AlertDialogTrigger asChild>
                            <DropdownMenuItem className="text-xs text-rose-500 focus:text-rose-600">
                              Delete
                            </DropdownMenuItem>
                          </AlertDialogTrigger>
                        </DropdownMenuContent>
                      </DropdownMenu>
                      <AlertDialogContent>
                        <AlertDialogHeader>
                          <AlertDialogTitle>Delete schedule</AlertDialogTitle>
                          <AlertDialogDescription>
                            Are you sure you want to delete this schedule? This
                            action cannot be undone.
                          </AlertDialogDescription>
                        </AlertDialogHeader>
                        <AlertDialogFooter>
                          <AlertDialogCancel>Cancel</AlertDialogCancel>
                          <AlertDialogAction
                            variant="destructive"
                            onClick={async () =>
                              await deleteSchedule({
                                workspaceId,
                                scheduleId: id!,
                              })
                            }
                          >
                            Confirm
                          </AlertDialogAction>
                        </AlertDialogFooter>
                      </AlertDialogContent>
                    </AlertDialog>
                  </div>
                </TableCell>
              </TableRow>
            ))
          ) : (
            <TableRow className="justify-center text-xs text-muted-foreground">
              <TableCell
                className="h-8 bg-muted-foreground/5 text-center"
                colSpan={4}
              >
                No Schedules
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
      <Separator />
      <CreateScheduleDialog workflowId={workflowId} />
    </div>
  )
}

const scheduleInputsSchema = z.object({
  duration: durationSchema,
  timeout: z.number().optional(),
})
type DurationType =
  | "duration.years"
  | "duration.months"
  | "duration.days"
  | "duration.hours"
  | "duration.minutes"
  | "duration.seconds"
type ScheduleInputs = z.infer<typeof scheduleInputsSchema>

export function CreateScheduleDialog({ workflowId }: { workflowId: string }) {
  const { createSchedule } = useSchedules(workflowId)
  const { workspaceId } = useWorkspace()
  const { workflow } = useWorkflow()
  const hasVersion = !!workflow?.version
  const form = useForm<ScheduleInputs>({
    resolver: zodResolver(scheduleInputsSchema),
  })

  const onSubmit = async (values: ScheduleInputs) => {
    if (!hasVersion) {
      toast({
        title: "Cannot create schedule",
        description: "You must commit the workflow before creating a schedule.",
        variant: "destructive",
      })
      return
    }

    const { duration, timeout } = values
    try {
      const response = await createSchedule({
        workspaceId,
        requestBody: {
          workflow_id: workflowId,
          every: durationToISOString(duration),
          timeout,
        },
      })
      console.log("Schedule created", response)
    } catch (error) {
      if (error instanceof ApiError) {
        console.error("Failed to create schedule", error.body)
      } else {
        console.error("Unexpected error when creating schedule", error)
      }
    }
  }

  return (
    <Dialog>
      <TooltipProvider>
        <Tooltip open={!hasVersion ? undefined : false}>
          <TooltipTrigger asChild>
            <span tabIndex={0}>
              <DialogTrigger asChild>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="flex h-7 w-full items-center justify-center gap-2 text-muted-foreground"
                  disabled={!hasVersion}
                >
                  <PlusCircleIcon className="size-4" />
                  <span>Create Schedule</span>
                </Button>
              </DialogTrigger>
            </span>
          </TooltipTrigger>
          <TooltipContent>
            <p>You must save the workflow before creating a schedule.</p>
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Create a new schedule</DialogTitle>
          <DialogDescription>
            Configure the schedule for the workflow. The workflow will not run
            immediately.
            {!hasVersion && (
              <p className="mt-2 text-rose-500">
                Warning: You must commit the workflow before creating a
                schedule.
              </p>
            )}
          </DialogDescription>
        </DialogHeader>
        <Form {...form}>
          <form
            className="space-y-4"
            onSubmit={form.handleSubmit(onSubmit, () => {
              console.error("Form validation failed")
              toast({
                title: "Invalid inputs in form",
                description: "Please check the form for errors.",
              })
            })}
          >
            <div className="grid grid-cols-2 gap-2">
              {[
                "duration.years",
                "duration.months",
                "duration.days",
                "duration.hours",
                "duration.minutes",
                "duration.seconds",
              ].map((unit) => (
                <FormField
                  key={unit}
                  control={form.control}
                  name={unit as DurationType}
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel className="text-xs capitalize text-foreground/80">
                        {unit.split(".")[1]}
                      </FormLabel>
                      <FormControl>
                        <Input
                          type="number"
                          className="text-xs capitalize"
                          placeholder={unit}
                          value={Math.max(0, Number(field.value || 0))}
                          {...form.register(unit as DurationType, {
                            valueAsNumber: true,
                          })}
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              ))}
            </div>
            <FormField
              key="timeout"
              control={form.control}
              name="timeout"
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-xs capitalize text-foreground/80">
                    Timeout
                  </FormLabel>
                  <FormDescription className="text-xs">
                    The maximum time in seconds the workflow can run for.
                  </FormDescription>
                  <FormControl>
                    <Input
                      type="number"
                      className="text-xs capitalize"
                      placeholder="Timeout (seconds)"
                      value={Math.max(1, Number(field.value || 300))}
                      {...form.register("timeout", {
                        valueAsNumber: true,
                      })}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <DialogFooter className="mt-4">
              <DialogClose asChild>
                <Button type="submit" variant="default">
                  <PlusCircleIcon className="mr-2 size-4" />
                  <span>Create</span>
                </Button>
              </DialogClose>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  )
}
