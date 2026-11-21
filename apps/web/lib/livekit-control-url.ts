export function liveKitControlUrl(publicSignalUrl: string) {
  return (process.env.LIVEKIT_INTERNAL_URL?.trim() || publicSignalUrl).replace(/^ws/, 'http')
}
