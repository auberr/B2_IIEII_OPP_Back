import cv2
import numpy as np
from PIL import Image as im

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'wetyle_share.settings')
django.setup()


# 유화 변환 함수. Image모델 id와 적용할 dnn모델 number
def styletransfer(idx, num):
    dnn_models = {
        1:"mosaic.t7",
        2:"candy.t7",
        3:"feathers.t7",
        4:"starry_night.t7",
        5:"la_muse.t7",
        6:"the_scream.t7",
        7:"udnie.t7"
        }
    
    dnn_model = dnn_models[int(num)]
    net = cv2.dnn.readNetFromTorch(f'models/instance_norm/{dnn_model}')

    # 등록한 이미지 불러옴
    target = Image.objects.get(id=idx)
    image_url = target.input_image
    img = cv2.imread(f'media/{image_url}')

    # 전처리
    h, w, c = img.shape

    MEAN_VALUE = [103.939, 116.779, 123.680]
    blob = cv2.dnn.blobFromImage(img, mean=MEAN_VALUE)

    net.setInput(blob)
    output = net.forward()

    output = output.squeeze().transpose((1, 2, 0))
    output += MEAN_VALUE

    output = np.clip(output, 0, 255)
    output = output.astype('uint8')

    # 이미지 저장하기 위해 np array를 이미지로 바꿔줌
    result_img = im.fromarray(output)
    

    # RGB 배치 필요
    # 이미지저장, db에도 저장
    result_img.save(f'media/results/{idx}.jpg', "JPEG")
    target.output_image = f'media/results/{idx}.jpg'
    target.save()