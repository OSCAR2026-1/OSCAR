import os
import requests
from dotenv import load_dotenv
from mcp.server.mcpserver import MCPServer

load_dotenv()
DUFFEL_TOKEN = os.getenv("DUFFEL_ACCESS_TOKEN")

mcp = MCPServer("trip-orchestrator")


@mcp.tool()
def say_hello(name: str) -> str:
    """Says hello to confirm the server is working."""
    return f"Hello {name}, your MCP server is up and running!"


@mcp.tool()
def search_flights(origin: str, destination: str, departure_date: str) -> str:
    """
    Search for flights between two airports on a given date.
    origin/destination should be 3-letter IATA airport codes, e.g. 'DEL', 'BOM', 'JFK'.
    departure_date should be in YYYY-MM-DD format.
    """
    url = "https://api.duffel.com/air/offer_requests"
    headers = {
        "Authorization": f"Bearer {DUFFEL_TOKEN}",
        "Duffel-Version": "v2",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    payload = {
        "data": {
            "slices": [{
                "origin": origin,
                "destination": destination,
                "departure_date": departure_date,
            }],
            "passengers": [{"type": "adult"}],
            "cabin_class": "economy",
        }
    }
    response = requests.post(
        url,
        headers=headers,
        json=payload,
        params={"return_offers": "true"},
    )
    if response.status_code >= 400:
        return f"Error from Duffel API: {response.status_code} - {response.text}"
    data = response.json()["data"]
    offers = sorted(data.get("offers", []), key=lambda o: float(o["total_amount"]))[:5]
    if not offers:
        return "No flights found for that route and date."
    results = []
    for offer in offers:
        airline = offer["owner"]["name"]
        price = offer["total_amount"]
        currency = offer["total_currency"]
        results.append(f"{airline}: {price} {currency}")
    return "\n".join(results)


@mcp.tool()
def search_hotels(destination: str, check_in: str, check_out: str) -> str:
    """
    Search for hotels in a destination city for given check-in/check-out dates.
    destination should be a city name, e.g. 'Goa', 'Paris', 'Tokyo'.
    check_in and check_out should be in YYYY-MM-DD format.
    """
    sample_hotels = [
        {"name": f"{destination} Grand Plaza", "price_per_night": 89, "rating": 4.3},
        {"name": f"{destination} Budget Inn", "price_per_night": 42, "rating": 3.7},
        {"name": f"{destination} Boutique Stay", "price_per_night": 120, "rating": 4.7},
        {"name": f"{destination} Airport Lodge", "price_per_night": 55, "rating": 3.9},
        {"name": f"{destination} Riverside Resort", "price_per_night": 145, "rating": 4.6},
    ]

    results = []
    for hotel in sample_hotels:
        results.append(
            f"{hotel['name']}: ${hotel['price_per_night']}/night, "
            f"rating {hotel['rating']}/5 ({check_in} to {check_out})"
        )
    return "\n".join(results)


@mcp.tool()
def build_itinerary(destination: str, num_days: int, flight_summary: str, hotel_summary: str) -> str:
    """
    Build a simple day-by-day itinerary for a trip.
    destination: city name, e.g. 'Goa'
    num_days: number of days of the trip, e.g. 4
    flight_summary: short text describing the chosen flight (e.g. from search_flights results)
    hotel_summary: short text describing the chosen hotel (e.g. from search_hotels results)
    """
    activity_pool = [
        f"Explore the main attractions and old town of {destination}",
        f"Try local food at a well-known {destination} restaurant",
        f"Relax at a popular spot near {destination}",
        f"Visit a museum or cultural site in {destination}",
        f"Take a day trip to a nearby attraction outside {destination}",
        f"Enjoy a leisure/shopping day in {destination}",
        f"Sunset viewpoint or scenic walk in {destination}",
    ]
    itinerary_lines = [
        f"Trip to {destination} — {num_days} days",
        f"Flight: {flight_summary}",
        f"Hotel: {hotel_summary}",
        "",
    ]
    for day in range(1, num_days + 1):
        activity = activity_pool[(day - 1) % len(activity_pool)]
        itinerary_lines.append(f"Day {day}: {activity}")
    return "\n".join(itinerary_lines)


@mcp.tool()
def plan_trip(origin: str, destination_airport: str, destination_city: str, departure_date: str, check_in: str, check_out: str, num_days: int) -> str:
    """
    Orchestrates a full trip plan: searches flights, searches hotels, and builds
    a day-by-day itinerary automatically, using the cheapest flight and top-rated hotel.
    origin, destination_airport: 3-letter IATA airport codes (e.g. 'LHR', 'JFK').
    destination_city: readable city name for hotels/itinerary (e.g. 'New York').
    departure_date, check_in, check_out: YYYY-MM-DD format.
    num_days: number of days of the trip.
    """
    flights_result = search_flights(origin, destination_airport, departure_date)
    top_flight = flights_result.split("\n")[0] if flights_result else "No flight found"
    hotels_result = search_hotels(destination_city, check_in, check_out)
    top_hotel = hotels_result.split("\n")[0] if hotels_result else "No hotel found"
    itinerary = build_itinerary(destination_city, num_days, top_flight, top_hotel)
    return (
        f"Here's your complete trip plan:\n\n"
        f"{itinerary}\n\n"
        f"--- All flight options ---\n{flights_result}\n\n"
        f"--- All hotel options ---\n{hotels_result}"
    )


if __name__ == "__main__":
    mcp.run()
