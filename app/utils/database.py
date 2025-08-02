from supabase import AsyncClient
from typing import Optional
from .logger import logger


async def insert_data(
    supabase: AsyncClient,
    table_name: str,
    data: dict,
    error_message: str = "An unexpected error occurred",
    model=None,
):
    try:
        # Await the execute() call
        response = await supabase.table(table_name).insert(data).execute()
        # Check Supabase response data if needed (optional)
        # if not response.data:
        #    logger.warning(f"Supabase insert to {table} returned no data.")

        if not model:
            return None  # Return None on success without model

        return model(error="")

    except Exception as e:
        # supabase errors are badly structured and must cast to string and parsed
        if "duplicate" in str(e).lower():
            if not model:
                return "duplicate"  # Keep returning string for duplicates without model
            return model(error=f"Duplicate entry")

        if not model:
            # Reraise the original exception for better debugging if no model
            logger.error(f"Error during insert to {table_name}: {e}")
            raise e  # Re-raise the original exception

        logger.error(f"{error_message}: {e}")
        return model(error=f"An unexpected error occurred")


async def query_data(
    supabase: AsyncClient,
    table_name: str,
    filters: dict = None,
    order_by: tuple = None,
    select_fields: str = "*",
    limit: Optional[int] = None,
    count: Optional[str] = None,
) -> AsyncClient:
    """
    Query a Supabase table with dynamic filters, ordering, limit, and count.

    :param table_name: Name of the table to query.
    :param filters: Dictionary where keys are column names and values are filter conditions.
                     Use a tuple (operator, value) for non-equality filters.
                     Supported operators: 'eq', 'in', 'gt', 'lt', 'gte', 'lte', 'like', 'ilike', 'neq', 'is'.  (# 'is': null/not null)
    :param order_by: Tuple (column_name, desc) where desc=True means descending order.
    :param select_fields: Fields to select (default is "*").
    :param limit: Optional integer to limit the number of results.
    :param count: Optional string to specify count method (e.g., 'exact').
    :return: Query result from Supabase.
    """
    query = supabase.table(table_name).select(select_fields, count=count)

    # Apply filters dynamically
    if filters:
        for key, condition in filters.items():
            if isinstance(condition, tuple):  # Special operator cases
                operator, value = condition
                if operator == "in":
                    query = query.in_(key, value)
                elif operator == "is":
                    query = query.is_(key, value)
                elif operator == "gt":
                    query = query.gt(key, value)
                elif operator == "lt":
                    query = query.lt(key, value)
                elif operator == "gte":
                    query = query.gte(key, value)
                elif operator == "lte":
                    query = query.lte(key, value)
                elif operator == "like":
                    query = query.like(key, value)
                elif operator == "ilike":
                    query = query.ilike(key, value)
                elif operator == "neq":
                    query = query.neq(key, value)
            else:  # Default to equality check
                query = query.eq(key, condition)

    # Apply ordering if provided
    if order_by:
        column, desc = order_by
        query = query.order(column, desc=desc)

    # Apply limit if provided
    if limit:
        query = query.limit(limit)

    # Await the execute() call
    return await query.execute()


async def update_data(
    supabase: AsyncClient,
    table_name: str,
    update_values: dict,
    filters: dict,
    error_message: str,
    model=None,
):
    """
    Updates records in a specified table based on provided filters.

    Parameters:
    - table: The name of the table to update
    - update_values: Dictionary of columns and values to update
    - filters: Dictionary of column-value pairs to filter by
    - error_message: Message to use for error reporting
    - model: Optional Pydantic model to wrap the response

    Returns:
    - If model is provided, returns an instance of the model
    - Otherwise, returns None on success or an error string on failure
    """
    try:
        # Start building the query
        query = supabase.table(table_name).update(update_values)

        # Apply filters dynamically, exactly like in query_data
        if filters:
            for key, condition in filters.items():
                if isinstance(condition, tuple):  # Special operator cases
                    operator, value = condition
                    if operator == "in":
                        query = query.in_(key, value)
                    elif operator == "gt":
                        query = query.gt(key, value)
                    elif operator == "lt":
                        query = query.lt(key, value)
                    elif operator == "gte":
                        query = query.gte(key, value)
                    elif operator == "lte":
                        query = query.lte(key, value)
                    elif operator == "like":
                        query = query.like(key, value)
                    elif operator == "ilike":
                        query = query.ilike(key, value)
                    elif operator == "neq":
                        query = query.neq(key, value)
                    elif operator == "is":
                        query = query.is_(key, value)
                else:  # Default to equality check
                    query = query.eq(key, condition)

        # Execute the update
        response = await query.execute()

        if not model:
            return None  # Indicate success
        return model(error="")

    except Exception as e:
        if not model:
            logger.error(f"Error updating {table_name}: {e}")
            raise e
        logger.error(f"Error in {error_message}: {e}")
        return model(error=f"An unexpected error occurred")


# New convenience helpers — keep API compatible with legacy routes
async def query_one(
    supabase: AsyncClient,
    table_name: str,
    match: dict | None = None,
    order_by: tuple | None = None,
    select_fields: str = "*",
):
    """Return the first (or *None*) row that matches the filters.

    This replicates the old helper that other route modules import.
    """
    resp = await query_data(
        supabase,
        table_name,
        filters=match or {},
        order_by=order_by,
        select_fields=select_fields,
        limit=1,
    )
    # Supabase Python client returns a .data attribute on the response object.
    rows = getattr(resp, "data", None) or []
    return rows[0] if rows else None


async def query_many(
    supabase: AsyncClient,
    table_name: str,
    match: dict | None = None,
    order_by: tuple | None = None,
    select_fields: str = "*",
    limit: int | None = None,
):
    """Return a list of rows that match the filters (empty list if none)."""
    resp = await query_data(
        supabase,
        table_name,
        filters=match or {},
        order_by=order_by,
        select_fields=select_fields,
        limit=limit,
    )
    return getattr(resp, "data", None) or []


# ---------------------------------------------------------------------------
# Backwards-compat shim for old call-signature used in legacy routes
# update_data(table, keys=..., values=...)
# ---------------------------------------------------------------------------
from inspect import signature

_original_update_data = update_data  # keep reference to the new implementation

async def update_data(
    supabase: AsyncClient,
    table_name: str,
    *,
    update_values: dict | None = None,
    filters: dict | None = None,
    keys: dict | None = None,
    values: dict | None = None,
    error_message: str = "Update failed",
    model=None,
):
    """Wrapper that supports both the new (update_values/filters) and the old
    (keys/values) keyword signature so existing routes keep working.
    """
    # Resolve legacy kwargs if present
    if keys is not None or values is not None:
        filters = keys or filters or {}
        update_values = values or update_values or {}

    # Delegate to the original implementation
    return await _original_update_data(
        supabase,
        table_name,
        update_values=update_values or {},
        filters=filters or {},
        error_message=error_message,
        model=model,
    )
