from django.contrib.auth.models import AnonymousUser
from django.shortcuts import get_object_or_404
from rest_framework import mixins, permissions, viewsets
from rest_framework.permissions import AllowAny
from django.db.models import F, Value, FloatField
from django.db.models.functions import Coalesce, Cast

from cves.constants import PRODUCT_SEPARATOR
from cves.models import Cve, Product, Vendor, Weakness
from cves.serializers import (
    CveDetailSerializer,
    CveListSerializer,
    ProductListSerializer,
    VendorListSerializer,
    WeaknessListSerializer,
)
from cves.utils import list_filtered_cves


def apply_cve_ordering(queryset, request):
    """Apply ordering from request params. Supports: updated_at, created_at, cvss"""
    sort = request.GET.get("sort", "-updated_at")

    # Simple date sorts
    if sort in ("updated_at", "-updated_at", "created_at", "-created_at"):
        return queryset.order_by(sort)

    # CVSS score sort - extract best score from JSON metrics
    # Priority: v4.0 > v3.1 > v3.0 > v2.0
    if sort in ("cvss", "-cvss"):
        queryset = queryset.annotate(
            cvss_score=Coalesce(
                Cast(F("metrics__cvssV4_0__data__score"), FloatField()),
                Cast(F("metrics__cvssV3_1__data__score"), FloatField()),
                Cast(F("metrics__cvssV3_0__data__score"), FloatField()),
                Cast(F("metrics__cvssV2_0__data__score"), FloatField()),
                Value(0.0, output_field=FloatField()),
            )
        )
        order = "-cvss_score" if sort == "-cvss" else "cvss_score"
        return queryset.order_by(order, "-updated_at")

    # Default
    return queryset.order_by("-updated_at")


class CveViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = CveListSerializer
    queryset = Cve.objects.all()
    lookup_field = "cve_id"
    permission_classes = [AllowAny]

    serializer_classes = {
        "list": CveListSerializer,
        "retrieve": CveDetailSerializer,
    }

    def get_queryset(self):
        if self.action == "retrieve":
            return self.queryset

        # For organization tokens, use AnonymousUser to avoid tag filtering
        user = getattr(self.request, "api_token", None)
        if user:
            user = AnonymousUser()
        else:
            user = self.request.user

        queryset = list_filtered_cves(self.request.GET, user)
        return apply_cve_ordering(queryset, self.request)

    def get_serializer_class(self):
        return self.serializer_classes.get(self.action, self.serializer_class)


class WeaknessViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = WeaknessListSerializer
    queryset = Weakness.objects.all().order_by("cwe_id")
    lookup_field = "cwe_id"
    permission_classes = [AllowAny]


class VendorViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = VendorListSerializer
    queryset = Vendor.objects.order_by("name").all()
    lookup_field = "name"
    lookup_url_kwarg = "name"
    permission_classes = [AllowAny]


class VendorCveViewSet(viewsets.GenericViewSet, mixins.ListModelMixin):
    serializer_class = CveListSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        vendor = get_object_or_404(Vendor, name=self.kwargs["vendor_name"])
        return (
            Cve.objects.order_by("-updated_at")
            .filter(vendors__contains=vendor.name)
            .all()
        )


class ProductViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ProductListSerializer
    lookup_field = "name"
    lookup_url_kwarg = "name"
    permission_classes = [AllowAny]

    def get_queryset(self):
        vendor = get_object_or_404(Vendor, name=self.kwargs["vendor_name"])
        return Product.objects.filter(vendor=vendor).order_by("name").all()


class ProductCveViewSet(viewsets.GenericViewSet, mixins.ListModelMixin):
    serializer_class = CveListSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        vendor = get_object_or_404(Vendor, name=self.kwargs["vendor_name"])
        product = get_object_or_404(
            Product, vendor=vendor, name=self.kwargs["product_name"]
        )
        return (
            Cve.objects.order_by("-updated_at")
            .filter(vendors__contains=f"{vendor}{PRODUCT_SEPARATOR}{product}")
            .all()
        )


class WeaknessCveViewSet(viewsets.GenericViewSet, mixins.ListModelMixin):
    serializer_class = CveListSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        weakness = get_object_or_404(Weakness, cwe_id=self.kwargs["weakness_cwe_id"])
        return (
            Cve.objects.order_by("-updated_at")
            .filter(weaknesses__contains=weakness.cwe_id)
            .all()
        )
