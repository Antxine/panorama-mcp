import { z } from "zod";
import { LOG_PERIODS, LOG_TYPES } from "../lib/logquery.js";

// Names are interpolated into XPath/XML; quotes and angle brackets are never valid in PAN-OS object names.
const safeName = z.string().min(1).max(127).regex(/^[^'"<>]+$/, "must not contain quotes or angle brackets");

export const managedDevice = safeName.describe(
  "Managed firewall behind Panorama: hostname (full or unique part) or serial number. Use panorama_list_firewalls to list them."
);

export const deviceGroupFilter = safeName
  .optional()
  .describe("Device group name (includes what it inherits from shared and parent groups), or 'shared'. When omitted, every location is searched.");

export const ipAddress = z
  .string()
  .regex(/^[0-9a-fA-F:.]+$/, "must be an IP address")
  .max(45)
  .describe("IP address");

export const userName = safeName.describe("User name, with or without domain (e.g. 'jdoe' or 'corp\\\\jdoe')");

export const urlInput = z
  .string()
  .min(1)
  .max(2048)
  .regex(/^[^\s'"<>]+$/, "must not contain spaces, quotes or angle brackets")
  .describe("URL or hostname, with or without scheme (e.g. 'https://app.example.com/login')");

export const logType = z.enum(LOG_TYPES).describe("Log type to search");

export const logPeriod = z
  .enum(LOG_PERIODS)
  .optional()
  .describe("Relative time window on receive_time (default: last-24-hrs)");

export const maxResults = z.number().int().min(1).max(500).optional().describe("Maximum entries returned (default: 50)");

export const port = z.number().int().min(0).max(65535);
