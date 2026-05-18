declare module 'three-spritetext' {
  import { Object3D } from 'three';

  export default class SpriteText extends Object3D {
    constructor(text?: string, textHeight?: number, color?: string);
    text: string;
    textHeight: number;
    color: string;
    backgroundColor: string | false;
    borderColor: string;
    borderWidth: number;
    borderRadius: number;
    padding: number | [number, number];
    fontFace: string;
    fontSize: number;
    fontWeight: string;
    strokeWidth: number;
    strokeColor: string;
    depthWrite: boolean;
    depthTest: boolean;
    opacity: number;
    getTextureSize(): { width: number; height: number };
  }
}
