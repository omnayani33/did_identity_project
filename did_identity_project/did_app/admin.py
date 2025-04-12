from django.contrib import admin
from .models import DID, FaceData, VerifiableCredential, BlockchainTransaction

@admin.register(DID)
class DIDAdmin(admin.ModelAdmin):
    list_display = ('did', 'user', 'created_at')
    search_fields = ('did', 'user__username')
    readonly_fields = ('did', 'public_key', 'encrypted_private_key', 'created_at', 'updated_at')

@admin.register(FaceData)
class FaceDataAdmin(admin.ModelAdmin):
    list_display = ('user', 'created_at')
    search_fields = ('user__username',)
    readonly_fields = ('face_encoding_path', 'face_image_path', 'created_at', 'updated_at')

@admin.register(VerifiableCredential)
class VerifiableCredentialAdmin(admin.ModelAdmin):
    list_display = ('id', 'credential_type', 'subject_did', 'issuer_did', 'status', 'issuance_date')
    list_filter = ('credential_type', 'status')
    search_fields = ('id', 'subject_did__user__username', 'issuer_did__user__username')
    readonly_fields = ('id', 'signature', 'blockchain_hash', 'blockchain_tx_id', 'issuance_date')

@admin.register(BlockchainTransaction)
class BlockchainTransactionAdmin(admin.ModelAdmin):
    list_display = ('tx_hash', 'credential_hash', 'block_number', 'timestamp')
    search_fields = ('tx_hash', 'credential_hash')
    readonly_fields = ('tx_hash', 'credential_hash', 'block_number', 'timestamp', 'data')
