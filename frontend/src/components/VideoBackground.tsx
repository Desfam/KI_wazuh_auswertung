type VideoBackgroundProps = {
  videoSource: string | null;
};

export function VideoBackground({ videoSource }: VideoBackgroundProps) {
  if (!videoSource) return null;

  return (
    <video
      src={videoSource}
      autoPlay
      loop
      muted
      playsInline
      className="absolute inset-0 h-full w-full object-cover opacity-100 saturate-[1.08] brightness-[0.9]"
    />
  );
}
