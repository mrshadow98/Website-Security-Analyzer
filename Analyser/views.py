from django.shortcuts import render

# Create your views here.
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from Analyser.models import RequestData
from Analyser.serializers import RequestDataSerializer


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def scan_url(request):
    if request.method == 'GET':
        url = request.GET.get("url")
        request_data = RequestData(url=url, user=request.user)
        request_data.save()
        serializer = RequestDataSerializer(request_data)
        return Response(serializer.data)


@api_view(['GET', 'DELETE'])
@permission_classes([IsAuthenticated])
def scan_url_detail(request, pk):
    try:
        item = RequestData.objects.get(pk=pk)
    except RequestData.DoesNotExist:
        return Response(status=404)

    if request.method == 'GET':
        serializer = RequestDataSerializer(item)
        return Response(serializer.data)

    elif request.method == 'DELETE':
        if not request.user.admin:
            return Response({'error': True, 'message': 'Not an admin account'}, status=401)
        item.delete()
        return Response(status=204)
