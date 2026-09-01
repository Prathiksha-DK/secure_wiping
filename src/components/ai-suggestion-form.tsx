"use client";

import { useState } from "react";
import { useFormState } from "react-dom";
import { Sparkles, Loader2, Info } from "lucide-react";
import { suggestWipeMethodAction } from "@/app/actions";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { Form, FormControl, FormField, FormItem, FormMessage } from "./ui/form";


const initialState = {
  wipeMethod: null,
  reasoning: null,
};

const formSchema = z.object({
  dataType: z.string().min(1, "Please select a data type."),
  securityLevel: z.string().min(1, "Please select a security level."),
});

export default function AiSuggestionForm() {
  const [state, formAction] = useFormState(suggestWipeMethodAction, initialState);
  const [isPending, setIsPending] = useState(false);

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      dataType: "",
      securityLevel: ""
    }
  });

  const onSubmit = async (values: z.infer<typeof formSchema>) => {
    setIsPending(true);
    const formData = new FormData();
    formData.append("dataType", values.dataType);
    formData.append("securityLevel", values.securityLevel);
    await formAction(formData);
    setIsPending(false);
  };

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
        <FormField
          control={form.control}
          name="dataType"
          render={({ field }) => (
            <FormItem>
              <Label>Data Type</Label>
              <Select onValueChange={field.onChange} defaultValue={field.value}>
                <FormControl>
                  <SelectTrigger>
                    <SelectValue placeholder="e.g., Personal files" />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  <SelectItem value="Personal files">Personal Files</SelectItem>
                  <SelectItem value="Sensitive documents">Sensitive Documents</SelectItem>
                  <SelectItem value="Full operating system">Full Operating System</SelectItem>
                </SelectContent>
              </Select>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="securityLevel"
          render={({ field }) => (
            <FormItem>
              <Label>Security Level</Label>
              <Select onValueChange={field.onChange} defaultValue={field.value}>
                <FormControl>
                  <SelectTrigger>
                    <SelectValue placeholder="e.g., Medium" />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  <SelectItem value="low">Low</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                </SelectContent>
              </Select>
              <FormMessage />
            </FormItem>
          )}
        />
        
        <Button type="submit" className="w-full" disabled={isPending}>
          {isPending ? (
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
          ) : (
            <Sparkles className="mr-2 h-4 w-4" />
          )}
          Get Suggestion
        </Button>
      </form>
       {state?.wipeMethod && (
        <Alert className="mt-4 border-teal-500 bg-teal-50 dark:bg-teal-900/20">
          <Info className="h-4 w-4 text-teal-600" />
          <AlertTitle className="text-teal-800 dark:text-teal-300">AI Recommendation: {state.wipeMethod}</AlertTitle>
          <AlertDescription className="text-teal-700 dark:text-teal-400">{state.reasoning}</AlertDescription>
        </Alert>
      )}
    </Form>
  );
}
