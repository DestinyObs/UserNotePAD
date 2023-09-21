using CloudinaryDotNet;
using CloudinaryDotNet.Actions;
using Microsoft.Extensions.Options;
using UserNotePAD.Helpers;
using UserNotePAD.Interfaces;

namespace ChatBIDApp.Services
{
    public class PhotoService : IPhotoService
    {
        private readonly Cloudinary _Cloudinary;

        //public PhotoService(IOptions<CloudinarySettings> config)
        //{
        //    var acc = new Account
        //    {
        //        Cloud = config.Value.CloudName,
        //        ApiKey = config.Value.ApiKey,
        //        ApiSecret = config.Value.ApiSecret
        //    };

        //    _Cloudinary = new Cloudinary(acc);
        //}

        public PhotoService(IOptions<CloudinarySettings> config)
        {
            var acc = new Account
            {
                Cloud = "diajdiurh",
                ApiKey = "245272367391712",
                ApiSecret = "_yGJIVp_KnqjekgXytEqpdlSE_A"
            };

            _Cloudinary = new Cloudinary(acc);


        }

        public async Task<ImageUploadResult> AddPhotoAsync(IFormFile file)
        {
            var uploadResult = new ImageUploadResult();

            if (file.Length <= 0)
            {
                return uploadResult;
            }

            // Check if the file size is within the allowed limit (1MB)
            if (file.Length > 1 * 1024 * 1024) 
            {
                return uploadResult;
            }

            using var stream = file.OpenReadStream();
            var uploadParams = new ImageUploadParams
            {
                File = new FileDescription(file.FileName, stream),
                Transformation = new Transformation()
                    .Height(161)
                    .Width(160)
                    .Crop("fill")
                    .Gravity("face")
            };

            uploadResult = await _Cloudinary.UploadAsync(uploadParams);

            return uploadResult;
        }
        public async Task<ImageUploadResult> AddCoverPhotoAsync(IFormFile file)
        {
            var uploadResult = new ImageUploadResult();

            if (file.Length <= 0)
            {
                return uploadResult;
            }

            // Check if the file size is within the allowed limit (1MB)
            if (file.Length > 2 * 1024 * 1024) 
            {
                return uploadResult;
            }

            using var stream = file.OpenReadStream();
            var uploadParams = new ImageUploadParams
            {
                File = new FileDescription(file.FileName, stream),
                Transformation = new Transformation()
                    .Height(260)
                    .Width(970)
                    .Crop("fill")
                    .Gravity("body")
            };

            uploadResult = await _Cloudinary.UploadAsync(uploadParams);

            return uploadResult;
        }
        public async Task<DeletionResult> DeletePhotoAsync(string PublicId)
        {
            var deleteParams = new DeletionParams(PublicId);
            var Result = await _Cloudinary.DestroyAsync(deleteParams);

            return Result;
        }



    }
}
