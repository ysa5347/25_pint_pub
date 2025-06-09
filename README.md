# 25_pint_pub
25-Operating_Systems; PintOS assignment publish

# PintOS Helper Script (helper.sh) 사용법

## 개요
`helper.sh`; PintOS path setting automation tool.

## 주요 기능

### 🔍 자동 감지 및 설정
- **PintOS 경로 자동 감지**: 일반적인 위치에서 PintOS 디렉토리를 자동으로 찾습니다
- **PATH 환경 변수 설정**: PintOS utils를 PATH에 자동 추가
- **파일 경로 자동 구성**: kernel.bin, loader.bin 경로를 올바르게 설정

### 🛠️ 환경 구성
- **QEMU 에뮬레이터 설정**: Bochs 대신 QEMU 사용하도록 설정
- **빌드 시스템 수정**: Makefile 설정 최적화
- **GDB 매크로 경로 설정**: 디버깅 환경 구성

### 📁 HW별 지원
- **HW1**: threads 프로젝트 설정
- **HW3**: userprog 프로젝트 설정  
- **HW4**: vm 프로젝트 설정

## 사용 방법

### 기본 실행
```bash
# 스크립트 실행 권한 부여
chmod +x helper.sh

# 스크립트 실행
source helper.sh
```

### 실행 과정
1. **HW 선택**: helper.sh 실행 시 HW 번호를 선택합니다. 
   ```
   select HW1 or HW3, HW4: 
   Choice(1/3/4): 4
   ```

2. **PintOS 경로 감지**: 자동으로 PintOS 디렉토리를 찾거나 수동 입력을 요청합니다

3. **자동 설정 실행**: 선택한 HW에 따라 필요한 설정을 자동으로 수행합니다

## 각 HW별 설정 내용

### HW1 (Threads)
- threads 디렉토리 빌드 설정
- alarm-multiple 테스트 실행
- 기본 PintOS 환경 구성

### HW3 (Userprog) 
- userprog 디렉토리 빌드 설정
- args-multiple 테스트 실행
- 사용자 프로그램 실행 환경 구성

### HW4 (VM)
- vm 디렉토리 빌드 설정  
- page-linear 테스트 실행
- 가상 메모리 관리 환경 구성

## 자동 수행되는 작업

### 📝 파일 수정
- `~/.bashrc`: PATH 환경 변수 추가
- `src/utils/pintos`: kernel.bin 경로 수정
- `src/utils/Pintos.pm`: loader.bin 경로 수정
- `src/utils/pintos-gdb`: GDB 매크로 경로 설정
- `src/threads/Make.vars`: 시뮬레이터를 qemu로 변경

## 주의사항

### ⚠️ 사전 요구사항
- Linux/Ubuntu 14.04 환경에서 git 설치 후 실행
- git clone으로 프로젝트 파일을 받은 후, project root directory name을 `25_pint_pub` -> `pintos`로 변경해야 잘 작동합니다. 변경하지 않아도 작동할 수 있으나, 시스템 상에 다른 `pintos` name의 directory가 있다면 잘못 인식될 수 있습니다.

### 🔄 재실행 시
- 스크립트는 중복 설정을 방지하는 로직을 포함
- PATH에 pintos/ directory가 이미 설정되어 있으면 경고 메시지만 표시

### 🐛 문제 해결
- **PintOS 경로를 찾지 못하는 경우**: 수동으로 전체 경로 입력
- **빌드 실패 시 즉시 exit**: 자세한 build error msg 열람이 필요할 땐 $ ./helper.sh 로 실행해서 build 과정에서 문제를 handle 해야 함
