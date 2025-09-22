"""Lead generation endpoints for capturing potential customers."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse

from app.models import LeadRequest, LeadResponse, MessageResponse
from app.utils.dependencies import get_supabase_async
from app.utils.database import insert_data, query_many
from app.utils.logger import logger

router = APIRouter(prefix="/v1/leads", tags=["leads"])

LEADS_TABLE = "leads"


@router.post("/", response_model=LeadResponse, status_code=201)
async def create_lead(
    request: LeadRequest,
    supabase=Depends(get_supabase_async),
):
    """Create a new lead from the contact form.
    
    This endpoint is public and doesn't require authentication to make it easy
    for potential customers to submit their information.
    """
    
    try:
        # Check if lead with this email already exists
        existing_leads = await query_many(
            supabase,
            LEADS_TABLE,
            match={"email": request.email},
            limit=1,
        )
        
        if existing_leads:
            # Update existing lead instead of creating duplicate
            existing_lead = existing_leads[0]
            logger.info(f"Updating existing lead for email: {request.email}")
            
            # For simplicity, we'll just return the existing lead
            # In production, you might want to update the description or track multiple submissions
            return LeadResponse(
                id=str(existing_lead["id"]),
                email=existing_lead["email"],
                company_name=existing_lead["company_name"],
                ai_agents_description=existing_lead["ai_agents_description"],
                created_at=datetime.fromisoformat(existing_lead["created_at"]),
                updated_at=datetime.fromisoformat(existing_lead["updated_at"]),
            )
        
        # Create new lead
        lead_data = {
            "email": request.email,
            "company_name": request.company_name,
            "ai_agents_description": request.ai_agents_description,
            # created_at/updated_at are handled by DB defaults
        }
        
        result = await insert_data(
            supabase,
            LEADS_TABLE,
            lead_data,
            error_message="Failed to create lead",
        )
        
        if result == "duplicate":
            # Race condition - another request created the lead
            raise HTTPException(
                status_code=409,
                detail="Lead with this email already exists"
            )
        
        # Fetch the created lead to return full data
        created_leads = await query_many(
            supabase,
            LEADS_TABLE,
            match={"email": request.email},
            limit=1,
        )
        
        if not created_leads:
            raise HTTPException(
                status_code=500,
                detail="Lead created but could not be retrieved"
            )
        
        created_lead = created_leads[0]
        logger.info(f"Created new lead for email: {request.email}, company: {request.company_name}")
        
        return LeadResponse(
            id=str(created_lead["id"]),
            email=created_lead["email"],
            company_name=created_lead["company_name"],
            ai_agents_description=created_lead["ai_agents_description"],
            created_at=datetime.fromisoformat(created_lead["created_at"]),
            updated_at=datetime.fromisoformat(created_lead["updated_at"]),
        )
        
    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        logger.error(f"Error creating lead: {e}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error while creating lead"
        )


@router.get("/", response_model=List[LeadResponse])
async def list_leads(
    supabase=Depends(get_supabase_async),
):
    """List all leads (admin endpoint).
    
    Note: This endpoint is currently public but should be protected with admin auth
    in production. For now, it's useful for testing and initial development.
    """
    
    try:
        leads = await query_many(
            supabase,
            LEADS_TABLE,
            match={},
            order_by=("created_at", "desc"),
            limit=100,  # Limit to prevent large responses
        )
        
        return [
            LeadResponse(
                id=str(lead["id"]),
                email=lead["email"],
                company_name=lead["company_name"],
                ai_agents_description=lead["ai_agents_description"],
                created_at=datetime.fromisoformat(lead["created_at"]),
                updated_at=datetime.fromisoformat(lead["updated_at"]),
            )
            for lead in leads
        ]
        
    except Exception as e:
        logger.error(f"Error listing leads: {e}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error while listing leads"
        )


@router.options("/")
async def leads_options():
    """Handle CORS preflight requests for lead submission."""
    return JSONResponse(
        content={},
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Max-Age": "600"
        }
    )


@router.get("/health")
async def health_check():
    """Simple health check endpoint for the leads service."""
    return JSONResponse(
        content={"status": "healthy", "service": "leads"},
        status_code=200
    )
