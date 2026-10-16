/**
 * Geographic Coordinate Utilities & Haversine Distance Calculations
 *
 * Provides pure, deterministic functions for:
 * 1. Validating latitude in [-90, 90] and longitude in [-180, 180].
 * 2. Calculating great-circle distance between two geographic coordinates using the Haversine formula.
 * 3. Calculating travel velocity in km/h from distance and positive elapsed time.
 *
 * Framework-agnostic and free of external runtime or paid dependencies.
 */

/** Earth's mean spherical radius in kilometers. */
export const EARTH_RADIUS_KM = 6371

/**
 * Default maximum plausible commercial human travel speed in km/h.
 * Commercial passenger jet cruise speed is ~850–920 km/h.
 * A threshold of 1000 km/h conservatively allows for high-altitude commercial flights
 * while flagging supersonic or impossible instant geographic transitions.
 */
export const DEFAULT_MAX_TRAVEL_SPEED_KM_H = 1000

/**
 * Default minimum travel distance in kilometers to evaluate impossible travel.
 * Prevents false positives caused by metropolitan ISP gateway switches,
 * cellular tower handovers, or small IP geolocation inaccuracies within the same city.
 */
export const DEFAULT_MIN_TRAVEL_DISTANCE_KM = 100

/**
 * Validates that latitude is within [-90, 90] and longitude is within [-180, 180].
 * Returns false for NaN, null, undefined, infinite, or out-of-range coordinates.
 */
export function isValidCoordinate(
  lat: number | null | undefined,
  lon: number | null | undefined,
): lat is number {
  if (lat === null || lat === undefined || lon === null || lon === undefined) {
    return false
  }
  if (typeof lat !== 'number' || typeof lon !== 'number') {
    return false
  }
  if (isNaN(lat) || isNaN(lon) || !isFinite(lat) || !isFinite(lon)) {
    return false
  }
  return lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180
}

/**
 * Calculates the great-circle distance between two geographic coordinates using the Haversine formula.
 *
 * Formula:
 *   a = sin²(Δlat/2) + cos(lat1) * cos(lat2) * sin²(Δlon/2)
 *   c = 2 * atan2(√a, √(1−a))
 *   d = R * c
 *
 * @param lat1 Latitude of first point in degrees [-90, 90]
 * @param lon1 Longitude of first point in degrees [-180, 180]
 * @param lat2 Latitude of second point in degrees [-90, 90]
 * @param lon2 Longitude of second point in degrees [-180, 180]
 * @returns Great-circle distance in kilometers
 */
export function haversineDistanceKm(
  lat1: number,
  lon1: number,
  lat2: number,
  lon2: number,
): number {
  const toRad = (deg: number) => (deg * Math.PI) / 180

  const dLat = toRad(lat2 - lat1)
  const dLon = toRad(lon2 - lon1)
  const phi1 = toRad(lat1)
  const phi2 = toRad(lat2)

  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(phi1) * Math.cos(phi2) * Math.sin(dLon / 2) * Math.sin(dLon / 2)

  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a))
  return EARTH_RADIUS_KM * c
}

/**
 * Calculates the minimum travel velocity in km/h required to travel between two points
 * given great-circle distance in km and elapsed time in milliseconds.
 *
 * Returns 0 if elapsed time is zero or negative, or distance is zero or negative.
 */
export function calculateTravelSpeedKmH(distanceKm: number, elapsedMs: number): number {
  if (elapsedMs <= 0 || distanceKm <= 0) return 0
  const hours = elapsedMs / (1000 * 60 * 60)
  return distanceKm / hours
}
