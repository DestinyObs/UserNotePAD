using CloudinaryDotNet.Actions;

namespace UserNotePAD.Interfaces
{
    public interface IPhotoService
    {
        Task<ImageUploadResult> AddPhotoAsync(IFormFile file);
        Task<ImageUploadResult> AddCoverPhotoAsync(IFormFile file);
        Task<DeletionResult> DeletePhotoAsync(string PublicId);

    }
}
