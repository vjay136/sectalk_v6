export const dynamic = 'force-dynamic'

const certificate = /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/

export function GET() {
  const configured = process.env.SECTALK_ANDROID_CERT_SHA256?.trim()
  const fingerprints = configured?.split(',').map(value => value.trim().toUpperCase())

  if (!fingerprints?.length || fingerprints.length > 4 || !fingerprints.every(value => certificate.test(value))) {
    return new Response(null, {status: 404, headers: {'Cache-Control': 'no-store'}})
  }

  return Response.json([{
    relation: ['delegate_permission/common.handle_all_urls'],
    target: {
      namespace: 'android_app',
      package_name: 'com.eaglesecurity.sectalk',
      sha256_cert_fingerprints: [...new Set(fingerprints)],
    },
  }], {headers: {'Cache-Control': 'public, max-age=300'}})
}
